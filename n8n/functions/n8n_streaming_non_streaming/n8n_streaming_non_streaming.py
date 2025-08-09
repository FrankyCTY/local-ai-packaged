"""
title: n8n Streaming
author: James @ foxbyte.tech (inspired by owndev)
author_url: https://github.com/webfox/
n8n_template: https://github.com/owndev/Open-WebUI-Functions/blob/master/pipelines/n8n/Open_WebUI_Test_Agent.json
version: 1.0.0
license: Apache License 2.0
description: A pipeline for interacting with N8N workflows with full streaming support. Seamlessly connects Open WebUI to N8N AI agents and workflows.
features:
  - Real-time streaming responses from N8N workflows
  - Filters out N8N metadata for clean output
  - Encrypted storage of sensitive API keys
  - Configurable status emissions
  - Supports both streaming and non-streaming N8N workflows
"""

import time
import aiohttp
import os
import base64
import hashlib
import logging
import json
from typing import Optional, Callable, Awaitable, Any, Dict
from pydantic import BaseModel, Field, GetCoreSchemaHandler
from cryptography.fernet import Fernet, InvalidToken
from open_webui.env import SRC_LOG_LEVELS
from pydantic_core import core_schema


class EncryptedStr(str):
    """A string type that automatically handles encryption/decryption"""

    @classmethod
    def _get_encryption_key(cls) -> Optional[bytes]:
        """Generate encryption key from WEBUI_SECRET_KEY environment variable"""
        secret = os.getenv("WEBUI_SECRET_KEY")
        if not secret:
            return None
        hashed_key = hashlib.sha256(secret.encode()).digest()
        return base64.urlsafe_b64encode(hashed_key)

    @classmethod
    def encrypt(cls, value: str) -> str:
        """Encrypt a string value"""
        if not value or value.startswith("encrypted:"):
            return value
        key = cls._get_encryption_key()
        if not key:
            return value
        f = Fernet(key)
        encrypted = f.encrypt(value.encode())
        return f"encrypted:{encrypted.decode()}"

    @classmethod
    def decrypt(cls, value: str) -> str:
        """Decrypt an encrypted string value"""
        if not value or not value.startswith("encrypted:"):
            return value
        key = cls._get_encryption_key()
        if not key:
            return value[len("encrypted:") :]
        try:
            encrypted_part = value[len("encrypted:") :]
            f = Fernet(key)
            decrypted = f.decrypt(encrypted_part.encode())
            return decrypted.decode()
        except (InvalidToken, Exception):
            return value

    @classmethod
    def __get_pydantic_core_schema__(
        cls, _source_type: Any, _handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        return core_schema.union_schema(
            [
                core_schema.is_instance_schema(cls),
                core_schema.chain_schema(
                    [
                        core_schema.str_schema(),
                        core_schema.no_info_plain_validator_function(
                            lambda value: cls(cls.encrypt(value) if value else value)
                        ),
                    ]
                ),
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda instance: str(instance)
            ),
        )

    def get_decrypted(self) -> str:
        """Get the decrypted value of this encrypted string"""
        return self.decrypt(self)


class Pipe:
    class Valves(BaseModel):
        N8N_URL: str = Field(
            default="https://your-n8n-instance.com/webhook/your-webhook-id",
            description="URL for the N8N webhook endpoint",
        )
        N8N_BEARER_TOKEN: EncryptedStr = Field(
            default="",
            description="Bearer token for authenticating with the N8N webhook (optional)",
        )
        INPUT_FIELD: str = Field(
            default="chatInput",
            description="Field name for the input message in the N8N payload",
        )
        RESPONSE_FIELD: str = Field(
            default="output",
            description="Field name for the response message in non-streaming N8N responses",
        )
        EMIT_INTERVAL: float = Field(
            default=1.0, description="Interval in seconds between status emissions"
        )
        ENABLE_STATUS_INDICATOR: bool = Field(
            default=True, description="Enable or disable status indicator emissions"
        )

    def __init__(self):
        self.name = "N8N Pipeline"
        self.valves = self.Valves()
        self.last_emit_time = 0
        self.log = logging.getLogger("n8n_pipeline")
        self.log.setLevel(SRC_LOG_LEVELS.get("N8N", logging.INFO))

    async def emit_status(
        self,
        event_emitter: Optional[Callable[[dict], Awaitable[None]]],
        level: str,
        message: str,
        done: bool = False,
    ) -> None:
        """Emit status updates to Open WebUI"""
        if not event_emitter or not self.valves.ENABLE_STATUS_INDICATOR:
            return

        current_time = time.time()
        if current_time - self.last_emit_time >= self.valves.EMIT_INTERVAL or done:
            await event_emitter(
                {
                    "type": "status",
                    "data": {
                        "status": "complete" if done else "in_progress",
                        "level": level,
                        "description": message,
                        "done": done,
                    },
                }
            )
            self.last_emit_time = current_time

    def extract_event_info(
        self, event_emitter: Optional[Callable]
    ) -> tuple[Optional[str], Optional[str]]:
        """Extract chat_id and message_id from event emitter closure"""
        if (
            not event_emitter
            or not hasattr(event_emitter, "__closure__")
            or not event_emitter.__closure__
        ):
            return None, None

        # chat_id, message_id metadata is stored in the __event_emitter__'s closure, a Python mechanism that allows a function to retain access to variables from its enclosing scope.
        for cell in event_emitter.__closure__:
            if hasattr(cell, "cell_contents") and isinstance(cell.cell_contents, dict):
                request_info = cell.cell_contents
                return request_info.get("chat_id"), request_info.get("message_id")
        return None, None

    def get_headers(self) -> Dict[str, str]:
        """Build HTTP headers for N8N request"""
        headers = {"Content-Type": "application/json"}

        bearer_token = self.valves.N8N_BEARER_TOKEN.get_decrypted()
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"

        return headers

    def parse_n8n_streaming_chunk(self, chunk_text: str) -> Optional[str]:
        """Parse N8N streaming chunk and extract content, filtering out metadata"""
        if not chunk_text.strip():
            return None

        try:
            data = json.loads(chunk_text.strip())

            if isinstance(data, dict):
                # Skip N8N metadata chunks
                chunk_type = data.get("type", "")
                if chunk_type in ["begin", "end", "error", "metadata"]:
                    self.log.debug(f"Skipping N8N metadata chunk: {chunk_type}")
                    return None

                # Skip metadata-only chunks
                if "metadata" in data and len(data) <= 2:
                    return None

                # Extract content from various possible field names
                content = (
                    data.get("text")
                    or data.get("content")
                    or data.get("output")
                    or data.get("message")
                    or data.get("delta")
                    or data.get("data")
                )

                # Handle OpenAI-style streaming format
                # USERNOTE: It could be like an OpenAI-compatible streaming object (choices[0].delta.content), extract that.
                if not content and "choices" in data:
                    choices = data.get("choices", [])
                    if choices and isinstance(choices[0], dict):
                        delta = choices[0].get("delta", {})
                        content = delta.get("content", "")

                if content:
                    return str(content)

                # Return non-metadata objects as strings
                if not any(
                    key in data for key in ["type", "metadata", "nodeId", "nodeName"]
                ):
                    return str(data)

        except json.JSONDecodeError:
            # Handle plain text content
            # USERNOTE: If that fails (malformed JSON) and the chunk does not even start with {, treat the whole thing as plain text and return it (so non-JSON lines such as hello world still work).
            # As this ensure user still see the generated text
            if not chunk_text.startswith("{"):
                return chunk_text.strip()

        return None

    def extract_content_from_mixed_stream(self, raw_text: str) -> str:
        """Extract content from mixed stream containing both metadata and content"""
        content_parts = []

        # Handle concatenated JSON objects
        parts = raw_text.split("}{")

        for i, part in enumerate(parts):
            # Reconstruct valid JSON
            if i > 0:
                part = "{" + part
            if i < len(parts) - 1:
                part = part + "}"

            extracted = self.parse_n8n_streaming_chunk(part)
            if extracted:
                content_parts.append(extracted)

        return "".join(content_parts)

    def build_payload(
        self,
        messages: list,
        user: Optional[dict],
        chat_id: Optional[str],
        message_id: Optional[str],
    ) -> dict:
        """Build the payload for N8N request
        Example result structure:
        {
                                                                "systemPrompt": "You are a helpful assistant",
                                                                "chat_id": "abc123",
                                                                "message_id": "msg456",
                                                                "user_id": "user789",
                                                                "user_email": "user@example.com",
                                                                "user_name": "John Doe",
                                                                "user_role": "admin",
                                                                "chatInput": "What's the weather?"
                                }
        """
        if not messages:
            return {}

        # Extract the user's question
        question = messages[-1]["content"]
        if "Prompt: " in question:
            question = question.split("Prompt: ")[-1]

        # Extract system prompt if available
        # Likely from the first message in the conversation messages
        system_prompt = ""
        if messages and messages[0].get("role") == "system":
            system_content = messages[0]["content"]
            if "Prompt: " in system_content:
                system_prompt = system_content.split("Prompt: ")[-1]
            else:
                system_prompt = system_content

        payload = {
            "systemPrompt": system_prompt,
            "chat_id": chat_id,
            "message_id": message_id,
        }

        # Add user information if available
        if user:
            payload.update(
                {
                    "user_id": user.get("id"),
                    "user_email": user.get("email"),
                    "user_name": user.get("name"),
                    "user_role": user.get("role"),
                }
            )

        # Add the main input field
        payload[self.valves.INPUT_FIELD] = question

        return payload

    def extract_non_streaming_response(self, response_data: Any) -> str:
        """Extract content from non-streaming N8N response"""
        # Handle array responses (common with "Respond to Webhook" + "allIncomingItems")
        if isinstance(response_data, list) and response_data:
            first_item = response_data[0]
            if isinstance(first_item, dict):
                return (
                    first_item.get(self.valves.RESPONSE_FIELD)
                    or first_item.get("text")
                    or first_item.get("content")
                    or first_item.get("output")
                    or str(first_item)
                )
            return str(first_item)

        # Handle dict responses
        if isinstance(response_data, dict):
            return (
                response_data.get(self.valves.RESPONSE_FIELD)
                or response_data.get("text")
                or response_data.get("content")
                or response_data.get("output")
                or str(response_data)
            )

        return str(response_data)

    async def pipe(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __event_emitter__: Optional[Callable[[dict], Awaitable[None]]] = None,
        __event_call__: Optional[Callable[[dict], Awaitable[dict]]] = None,
    ) -> str:
        """Main pipeline function"""

        await self.emit_status(
            __event_emitter__, "info", f"Initializing {self.name}..."
        )

        messages = body.get("messages", [])
        if not messages:
            error_msg = "No messages found in the request body"
            self.log.warning(error_msg)
            await self.emit_status(__event_emitter__, "error", error_msg, True)
            return error_msg

        n8n_response = ""

        try:
            # Extract request information
            chat_id, message_id = self.extract_event_info(__event_emitter__)

            # Build request payload
            payload = self.build_payload(messages, __user__, chat_id, message_id)
            headers = self.get_headers()

            self.log.info(f"Sending request to N8N: {self.valves.N8N_URL}")
            await self.emit_status(
                __event_emitter__, "info", "Processing with N8N workflow..."
            )

            async with aiohttp.ClientSession(
                trust_env=True,
                timeout=aiohttp.ClientTimeout(total=None),
            ) as session:
                async with session.post(
                    self.valves.N8N_URL, json=payload, headers=headers
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise Exception(
                            f"N8N returned HTTP {response.status}: {error_text}"
                        )

                    # Check if the response is streaming
                    content_type = response.headers.get("Content-Type", "").lower()
                    is_streaming = (
                        "stream" in content_type
                        or "text/plain" in content_type
                        or response.headers.get("Transfer-Encoding") == "chunked"
                    )

                    if is_streaming:
                        # --- STREAMING MODE ---
                        self.log.info("Processing streaming response from N8N")
                        buffer = ""

                        # USERNOTE: iter_any() does zero post-processing—it just hands you the raw TCP byte chunks exactly as they come off the socket. No line splitting, no decoding, no buffering until a delimiter, nothing.
                        async for chunk in response.content.iter_any():
                            if not chunk:
                                continue
                            # USERNOTE: =========== Chunk Processing: Loop for each received chunk ===========

                            # USERNOTE: Converts those bytes to a Python str using UTF-8 (the default codec).
                            text = chunk.decode(errors="ignore")
                            buffer += text

                            # Process complete JSON objects
                            while True:
                                start_idx = buffer.find("{")
                                # USERNOTE: If no opening brace is found, the loop breaks and the next chunk is processed.
                                if start_idx == -1:
                                    break

                                # Find matching closing brace
                                brace_count = 0
                                end_idx = -1

                                # USERNOTE: Iterates over the buffer from the opening brace to the end of the buffer.
                                for i in range(start_idx, len(buffer)):
                                    if buffer[i] == "{":
                                        brace_count += 1
                                    elif buffer[i] == "}":
                                        brace_count -= 1
                                        if brace_count == 0:
                                            end_idx = i
                                            break

                                # USERNOTE: If no closing brace is found, the loop breaks and the next chunk is processed.
                                if end_idx == -1:
                                    # Incomplete JSON, wait for more data
                                    break

                                # Extract and process the JSON chunk
                                # USERNOTE: Extract JSON chunk from THIS CHUNK: Take every character in the string buffer starting at position start_idx up to, but not including, position end_idx + 1.
                                json_chunk = buffer[start_idx : end_idx + 1]

                                # USERNOTE: The slice buffer[end_idx + 1 :] keeps whatever is left after the last fully-balanced JSON object we just extracted.
                                # By preserving it in buffer, the next iteration of the outer async for chunk … loop will append more bytes to it, and the brace-matching logic will try again to find another complete JSON object.
                                #
                                # That remainder could be:
                                # - the start of the next JSON object,
                                # - a partial JSON object that is still arriving,
                                # - random text that came after the JSON, or
                                # - any mixture of the above.
                                buffer = buffer[end_idx + 1 :]

                                # USERNOTE: Parse the JSON chunk and extract the content.
                                # Then send chat message delta message to Open WebUI via event emitter.
                                content = self.parse_n8n_streaming_chunk(json_chunk)
                                if content:
                                    n8n_response += content

                                    if __event_emitter__:
                                        await __event_emitter__(
                                            {
                                                "type": "chat:message:delta",
                                                "data": {
                                                    "role": "assistant",
                                                    "content": content,
                                                },
                                            }
                                        )

                        # Process any remaining content in buffer
                        if buffer.strip():
                            remaining_content = self.extract_content_from_mixed_stream(
                                buffer
                            )
                            if remaining_content:
                                n8n_response += remaining_content
                                if __event_emitter__:
                                    await __event_emitter__(
                                        {
                                            "type": "chat:message:delta",
                                            "data": {
                                                "role": "assistant",
                                                "content": remaining_content,
                                            },
                                        }
                                    )

                        # Emit final complete message
                        if n8n_response and __event_emitter__:
                            await __event_emitter__(
                                {
                                    "type": "chat:message",
                                    "data": {
                                        "role": "assistant",
                                        "content": n8n_response,
                                    },
                                }
                            )
                    else:
                        # --- NON-STREAMING MODE ---
                        self.log.info("Processing non-streaming response from N8N")

                        try:
                            response_data = await response.json()
                            n8n_response = self.extract_non_streaming_response(
                                response_data
                            )
                        except json.JSONDecodeError:
                            # Fall back to text response
                            raw_text = await response.text()
                            n8n_response = (
                                self.extract_content_from_mixed_stream(raw_text)
                                or raw_text
                            )

        except Exception as e:
            error_msg = f"N8N pipeline error: {str(e)}"
            self.log.exception(error_msg)
            await self.emit_status(__event_emitter__, "error", error_msg, True)
            return error_msg

        # Update conversation with response
        body["messages"].append({"role": "assistant", "content": n8n_response})
        await self.emit_status(
            __event_emitter__, "info", "N8N processing complete", True
        )

        return n8n_response
