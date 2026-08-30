import { randomUUID } from "crypto";
import type { PublicFeedbackEntry, PublicFeedbackReaction } from "./storage-types";
import { sanitizeStoredFeedbackReactionActor } from "./storage-utils";

export type PublicFeedbackView = {
  id: string;
  message: string;
  createdAt: number;
  likes: number;
  dislikes: number;
  score: number;
};

export class PublicFeedbackStore {
  private feedback: Map<string, PublicFeedbackEntry> = new Map();
  private reactions: Map<string, Map<string, PublicFeedbackReaction>> = new Map();

  private toView(entry: PublicFeedbackEntry): PublicFeedbackView {
    const reactions = this.reactions.get(entry.id) || new Map<string, PublicFeedbackReaction>();
    let likes = 0;
    let dislikes = 0;
    reactions.forEach((value) => {
      if (value === "like") likes += 1;
      if (value === "dislike") dislikes += 1;
    });
    return {
      id: entry.id,
      message: entry.message,
      createdAt: entry.createdAt,
      likes,
      dislikes,
      score: likes - dislikes,
    };
  }

  list(): PublicFeedbackView[] {
    return Array.from(this.feedback.values())
      .map((entry) => this.toView(entry))
      .sort((a, b) => {
        if (b.score !== a.score) return b.score - a.score;
        if (b.likes !== a.likes) return b.likes - a.likes;
        return b.createdAt - a.createdAt;
      });
  }

  add(message: string): PublicFeedbackView {
    const normalized = String(message || "").trim().replace(/\s+/g, " ");
    if (!normalized) throw new Error("Feedback message is required");
    if (normalized.length > 1200) throw new Error("Feedback message is too long");
    const entry: PublicFeedbackEntry = {
      id: randomUUID(),
      message: normalized,
      createdAt: Date.now(),
    };
    this.feedback.set(entry.id, entry);
    this.reactions.set(entry.id, new Map());
    return this.toView(entry);
  }

  react(id: string, clientId: string, reaction: PublicFeedbackReaction): PublicFeedbackView | undefined {
    const feedbackId = String(id || "").trim();
    const actor = sanitizeStoredFeedbackReactionActor(clientId);
    if (!feedbackId) throw new Error("Feedback id is required");
    if (!actor) throw new Error("Client id is required");
    if (reaction !== "like" && reaction !== "dislike" && reaction !== "clear") throw new Error("Invalid reaction");
    const entry = this.feedback.get(feedbackId);
    if (!entry) return undefined;
    const reactions = this.reactions.get(feedbackId) || new Map<string, PublicFeedbackReaction>();
    if (reaction === "clear") {
      reactions.delete(actor);
    } else {
      reactions.set(actor, reaction);
    }
    this.reactions.set(feedbackId, reactions);
    return this.toView(entry);
  }

  exportSnapshot(redactSensitiveState: boolean): {
    publicFeedback: Array<[string, PublicFeedbackEntry]>;
    publicFeedbackReactions: Array<[string, Array<[string, PublicFeedbackReaction]>]>;
  } {
    return {
      publicFeedback: Array.from(this.feedback.entries()),
      publicFeedbackReactions: redactSensitiveState
        ? []
        : Array.from(this.reactions.entries()).map(([feedbackId, reactions]) => [
            feedbackId,
            Array.from(reactions.entries()),
          ]),
    };
  }

  importSnapshot(data: {
    publicFeedback?: unknown;
    publicFeedbackReactions?: unknown;
    redactSensitiveState: boolean;
  }): void {
    this.feedback = toMap<PublicFeedbackEntry>(data.publicFeedback);
    this.reactions = new Map();
    if (data.redactSensitiveState || !Array.isArray(data.publicFeedbackReactions)) return;
    for (const row of data.publicFeedbackReactions) {
      if (!Array.isArray(row) || row.length !== 2) continue;
      const feedbackId = String(row[0] || "").trim();
      if (!feedbackId) continue;
      const entries = Array.isArray(row[1]) ? row[1] : [];
      const mapped = new Map<string, PublicFeedbackReaction>();
      for (const pair of entries) {
        if (!Array.isArray(pair) || pair.length !== 2) continue;
        const clientId = sanitizeStoredFeedbackReactionActor(String(pair[0] || "").trim());
        const reaction = String(pair[1] || "").trim();
        if (!clientId) continue;
        if (reaction !== "like" && reaction !== "dislike") continue;
        mapped.set(clientId, reaction as PublicFeedbackReaction);
      }
      this.reactions.set(feedbackId, mapped);
    }
  }

  reset(): void {
    this.feedback.clear();
    this.reactions.clear();
  }
}

export function listPublicFeedbackForStorageScoped(store: PublicFeedbackStore): PublicFeedbackView[] {
  return store.list();
}

export function addPublicFeedbackForStorageScoped(
  store: PublicFeedbackStore,
  message: string,
): PublicFeedbackView {
  return store.add(message);
}

export function reactPublicFeedbackForStorageScoped(params: {
  store: PublicFeedbackStore;
  id: string;
  clientId: string;
  reaction: PublicFeedbackReaction;
}): PublicFeedbackView | undefined {
  return params.store.react(params.id, params.clientId, params.reaction);
}

function toMap<T>(entries: unknown): Map<string, T> {
  if (!Array.isArray(entries)) return new Map<string, T>();
  return new Map<string, T>(entries.filter((entry) => Array.isArray(entry) && entry.length === 2));
}
