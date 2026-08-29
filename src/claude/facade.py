"""High-level Claude Code integration facade.

Provides simple interface for bot handlers.
"""

import asyncio
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import structlog

from ..config.settings import Settings
from .sdk_integration import ClaudeResponse, ClaudeSDKManager, StreamUpdate
from .session import SessionManager

logger = structlog.get_logger()

# Sent back into the same session when a run stops at the turn/budget limit
# before writing an answer.
CONTINUE_PROMPT = (
    "You stopped at the turn limit without answering. Continue from where you "
    "left off and give the final answer to the original request. "
    "Do not start over."
)

# Shown when even the continuation produced nothing.
LIMIT_REACHED_MSG = (
    "⚠️ Hit the turn limit ({num_turns}) before producing an answer. "
    'Say "continue" and I will finish the job.'
)


class ClaudeIntegration:
    """Main integration point for Claude Code."""

    def __init__(
        self,
        config: Settings,
        sdk_manager: Optional[ClaudeSDKManager] = None,
        session_manager: Optional[SessionManager] = None,
    ):
        """Initialize Claude integration facade."""
        self.config = config
        self.sdk_manager = sdk_manager or ClaudeSDKManager(config)
        self.session_manager = session_manager

    async def run_command(
        self,
        prompt: str,
        working_directory: Path,
        user_id: int,
        session_id: Optional[str] = None,
        on_stream: Optional[Callable[[StreamUpdate], None]] = None,
        force_new: bool = False,
        interrupt_event: Optional["asyncio.Event"] = None,
        images: Optional[List[Dict[str, str]]] = None,
    ) -> ClaudeResponse:
        """Run Claude Code command with full integration."""
        logger.info(
            "Running Claude command",
            user_id=user_id,
            working_directory=str(working_directory),
            session_id=session_id,
            prompt_length=len(prompt),
            force_new=force_new,
        )

        # If no session_id provided, try to find an existing session for this
        # user+directory combination (auto-resume).
        # Skip auto-resume when force_new is set (e.g. after /new command).
        if not session_id and not force_new:
            existing_session = await self._find_resumable_session(
                user_id, working_directory
            )
            if existing_session:
                session_id = existing_session.session_id
                logger.info(
                    "Auto-resuming existing session for project",
                    session_id=session_id,
                    project_path=str(working_directory),
                    user_id=user_id,
                )

        # Get or create session
        session = await self.session_manager.get_or_create_session(
            user_id, working_directory, session_id
        )

        # Execute command
        try:
            # Continue session if we have an existing session with a real ID
            is_new = getattr(session, "is_new_session", False)
            should_continue = not is_new and bool(session.session_id)

            # For new sessions, don't pass session_id to Claude Code
            claude_session_id = session.session_id if should_continue else None

            try:
                response = await self._execute(
                    prompt=prompt,
                    working_directory=working_directory,
                    session_id=claude_session_id,
                    continue_session=should_continue,
                    stream_callback=on_stream,
                    interrupt_event=interrupt_event,
                    images=images,
                )
            except Exception as resume_error:
                # If resume failed (e.g., session expired/missing on Claude's side),
                # retry as a fresh session.  The CLI returns a generic exit-code-1
                # when the session is gone, so we catch *any* error during resume.
                if should_continue:
                    logger.warning(
                        "Session resume failed, starting fresh session",
                        failed_session_id=claude_session_id,
                        error=str(resume_error),
                    )
                    # Clean up the stale session
                    await self.session_manager.remove_session(session.session_id)

                    # Create a fresh session and retry
                    session = await self.session_manager.get_or_create_session(
                        user_id, working_directory
                    )
                    response = await self._execute(
                        prompt=prompt,
                        working_directory=working_directory,
                        session_id=None,
                        continue_session=False,
                        stream_callback=on_stream,
                        interrupt_event=interrupt_event,
                        images=images,
                    )
                else:
                    raise

            # A run that stopped at the turn/budget limit without an answer is
            # not a finished task.  Resume the same session once so the user
            # gets a real reply instead of silence.
            auto_continued = False
            if (
                self.config.claude_auto_continue_on_max_turns
                and response.stopped_at_limit
                and not response.content.strip()
                and not response.interrupted
                and (interrupt_event is None or not interrupt_event.is_set())
            ):
                auto_continued = True
                logger.warning(
                    "Run stopped at limit without an answer, auto-continuing",
                    subtype=response.subtype,
                    num_turns=response.num_turns,
                    session_id=response.session_id,
                    user_id=user_id,
                )
                await self._notify_stream(on_stream, "Hit the turn limit, continuing…")
                response = await self._continue_after_limit(
                    first=response,
                    working_directory=working_directory,
                    stream_callback=on_stream,
                    interrupt_event=interrupt_event,
                )

            # Update session (assigns real session_id for new sessions)
            await self.session_manager.update_session(session, response)

            # Ensure response has the session's final ID
            response.session_id = session.session_id

            if not response.session_id:
                logger.warning(
                    "No session_id after execution; session cannot be resumed",
                    user_id=user_id,
                )

            logger.info(
                "Claude command completed",
                session_id=response.session_id,
                cost=response.cost,
                duration_ms=response.duration_ms,
                num_turns=response.num_turns,
                is_error=response.is_error,
                subtype=response.subtype,
                stopped_at_limit=response.stopped_at_limit,
                content_length=len(response.content),
                auto_continued=auto_continued,
            )

            return response

        except Exception as e:
            logger.error(
                "Claude command failed",
                error=str(e),
                user_id=user_id,
                session_id=session.session_id,
            )
            raise

    async def _notify_stream(
        self,
        on_stream: Optional[Callable[[StreamUpdate], Any]],
        text: str,
    ) -> None:
        """Show a progress note to the user without failing the run."""
        if on_stream is None:
            return
        try:
            result = on_stream(StreamUpdate(type="assistant", content=text))
            if asyncio.iscoroutine(result):
                await result
        except Exception as e:  # progress is best-effort
            logger.debug("Progress notification failed", error=str(e))

    async def _continue_after_limit(
        self,
        first: ClaudeResponse,
        working_directory: Path,
        stream_callback: Optional[Callable] = None,
        interrupt_event: Optional[asyncio.Event] = None,
    ) -> ClaudeResponse:
        """Resume a run that stopped at a limit, once, and merge the results.

        Never recurses: the merged response is returned as-is, whatever the
        second attempt produced.
        """
        try:
            second = await self._execute(
                prompt=CONTINUE_PROMPT,
                working_directory=working_directory,
                session_id=first.session_id or None,
                continue_session=bool(first.session_id),
                stream_callback=stream_callback,
                interrupt_event=interrupt_event,
            )
        except Exception as e:
            logger.warning(
                "Auto-continue after limit failed",
                error=str(e),
                session_id=first.session_id,
            )
            first.content = LIMIT_REACHED_MSG.format(num_turns=first.num_turns)
            return first

        merged_content = "\n\n".join(
            part for part in (first.content.strip(), second.content.strip()) if part
        )
        total_turns = first.num_turns + second.num_turns
        if not merged_content:
            merged_content = LIMIT_REACHED_MSG.format(num_turns=total_turns)

        second.content = merged_content
        second.cost = first.cost + second.cost
        second.duration_ms = first.duration_ms + second.duration_ms
        second.num_turns = total_turns
        second.tools_used = first.tools_used + second.tools_used
        second.session_id = second.session_id or first.session_id
        return second

    async def _execute(
        self,
        prompt: str,
        working_directory: Path,
        session_id: Optional[str] = None,
        continue_session: bool = False,
        stream_callback: Optional[Callable] = None,
        interrupt_event: Optional[asyncio.Event] = None,
        images: Optional[List[Dict[str, str]]] = None,
    ) -> ClaudeResponse:
        """Execute command via SDK."""
        return await self.sdk_manager.execute_command(
            prompt=prompt,
            working_directory=working_directory,
            session_id=session_id,
            continue_session=continue_session,
            stream_callback=stream_callback,
            interrupt_event=interrupt_event,
            images=images,
        )

    async def _find_resumable_session(
        self,
        user_id: int,
        working_directory: Path,
    ) -> Optional["ClaudeSession"]:  # noqa: F821
        """Find the most recent resumable session for a user in a directory.

        Returns the session if one exists that is non-expired and has a real
        (non-temporary) session ID from Claude. Returns None otherwise.
        """

        sessions = await self.session_manager._get_user_sessions(user_id)

        matching_sessions = [
            s
            for s in sessions
            if s.project_path == working_directory
            and bool(s.session_id)
            and not s.is_expired(self.config.session_timeout_hours)
        ]

        if not matching_sessions:
            return None

        return max(matching_sessions, key=lambda s: s.last_used)

    async def continue_session(
        self,
        user_id: int,
        working_directory: Path,
        prompt: Optional[str] = None,
        on_stream: Optional[Callable[[StreamUpdate], None]] = None,
    ) -> Optional[ClaudeResponse]:
        """Continue the most recent session."""
        logger.info(
            "Continuing session",
            user_id=user_id,
            working_directory=str(working_directory),
            has_prompt=bool(prompt),
        )

        # Get user's sessions
        sessions = await self.session_manager._get_user_sessions(user_id)

        # Find most recent session in this directory (exclude sessions without IDs)
        matching_sessions = [
            s
            for s in sessions
            if s.project_path == working_directory and bool(s.session_id)
        ]

        if not matching_sessions:
            logger.info("No matching sessions found", user_id=user_id)
            return None

        # Get most recent
        latest_session = max(matching_sessions, key=lambda s: s.last_used)

        # Continue session with default prompt if none provided
        # Claude CLI requires a prompt, so we use a placeholder
        return await self.run_command(
            prompt=prompt or "Please continue where we left off",
            working_directory=working_directory,
            user_id=user_id,
            session_id=latest_session.session_id,
            on_stream=on_stream,
        )

    async def get_session_info(
        self, session_id: str, user_id: int
    ) -> Optional[Dict[str, Any]]:
        """Get session information (scoped to requesting user)."""
        return await self.session_manager.get_session_info(session_id, user_id)

    async def get_user_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all sessions for a user."""
        sessions = await self.session_manager._get_user_sessions(user_id)
        return [
            {
                "session_id": s.session_id,
                "project_path": str(s.project_path),
                "created_at": s.created_at.isoformat(),
                "last_used": s.last_used.isoformat(),
                "total_cost": s.total_cost,
                "message_count": s.message_count,
                "tools_used": s.tools_used,
                "expired": s.is_expired(self.config.session_timeout_hours),
            }
            for s in sessions
        ]

    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions."""
        return await self.session_manager.cleanup_expired_sessions()

    async def get_user_summary(self, user_id: int) -> Dict[str, Any]:
        """Get comprehensive user summary."""
        session_summary = await self.session_manager.get_user_session_summary(user_id)

        return {
            "user_id": user_id,
            **session_summary,
        }

    async def shutdown(self) -> None:
        """Shutdown integration and cleanup resources."""
        logger.info("Shutting down Claude integration")

        await self.cleanup_expired_sessions()

        logger.info("Claude integration shutdown complete")
