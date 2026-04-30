import Anthropic from "@anthropic-ai/sdk";

import type {
    ChatRequest,
    ChatResponse,
    ContentBlock,
    LLM,
    Message,
} from "./types.js";

// Anthropic adapter. Wires cache_control onto the system prompt and the
// last tool definition so the entire stable prefix (system + tools) is
// cached. Per-turn dynamic content (messages[]) sits outside the cache
// boundary and doesn't invalidate it.

export class AnthropicLLM implements LLM {
    private client: Anthropic;

    constructor(apiKey: string) {
        this.client = new Anthropic({ apiKey });
    }

    name() { return "anthropic"; }

    pricing(model: string) {
        // USD per 1M tokens. Source: anthropic.com/pricing as of 2026-04.
        if (model.startsWith("claude-opus-4-7")) {
            return { input: 15, output: 75, cache_read: 1.5, cache_write: 18.75 };
        }
        if (model.startsWith("claude-sonnet-4-6")) {
            return { input: 3, output: 15, cache_read: 0.3, cache_write: 3.75 };
        }
        if (model.startsWith("claude-haiku-4-5")) {
            return { input: 1, output: 5, cache_read: 0.1, cache_write: 1.25 };
        }
        return { input: 3, output: 15 };
    }

    async chat(req: ChatRequest): Promise<ChatResponse> {
        const tools = req.tools.map((t, i) => ({
            name: t.name,
            description: t.description,
            input_schema: t.input_schema as Anthropic.Tool.InputSchema,
            // Cache breakpoint on the last tool — Anthropic caches everything
            // up to and including the breakpoint, so this catches system + tools.
            ...(i === req.tools.length - 1
                ? { cache_control: { type: "ephemeral" as const } }
                : {}),
        }));

        const system = [
            {
                type: "text" as const,
                text: req.system,
                cache_control: { type: "ephemeral" as const },
            },
        ];

        const messages: Anthropic.MessageParam[] = req.messages.map((m) => ({
            role: m.role,
            content: m.content.map(toAnthropicBlock),
        }));

        const resp = await this.client.messages.create({
            model: req.model,
            max_tokens: req.max_tokens,
            temperature: req.temperature,
            system,
            tools,
            messages,
        });

        const content: ContentBlock[] = resp.content.map((b) => {
            if (b.type === "text") return { type: "text", text: b.text };
            if (b.type === "tool_use") {
                return {
                    type: "tool_use",
                    id: b.id,
                    name: b.name,
                    input: (b.input ?? {}) as Record<string, unknown>,
                };
            }
            // Anthropic responses don't contain tool_result or other server-side
            // block types. Fall through to text so an unexpected variant is
            // visible rather than silently dropped.
            return { type: "text", text: JSON.stringify(b) };
        });

        return {
            content,
            stop_reason: (resp.stop_reason ?? "other") as ChatResponse["stop_reason"],
            usage: {
                input_tokens: resp.usage.input_tokens,
                output_tokens: resp.usage.output_tokens,
                cache_creation_input_tokens: resp.usage.cache_creation_input_tokens ?? 0,
                cache_read_input_tokens: resp.usage.cache_read_input_tokens ?? 0,
            },
            model: resp.model,
        };
    }
}

function toAnthropicBlock(b: ContentBlock): Anthropic.ContentBlockParam {
    switch (b.type) {
        case "text":
            return { type: "text", text: b.text };
        case "tool_use":
            return { type: "tool_use", id: b.id, name: b.name, input: b.input };
        case "tool_result":
            return {
                type: "tool_result",
                tool_use_id: b.tool_use_id,
                content: b.content,
                is_error: b.is_error,
            };
    }
}

export function buildUserMessage(text: string): Message {
    return { role: "user", content: [{ type: "text", text }] };
}
