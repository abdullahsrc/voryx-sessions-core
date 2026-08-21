import { randomUUID } from "crypto";
import type { Task } from "@shared/schema";

export type CreateSessionTaskInput = {
  sessionId: string;
  title: string;
  description: string;
  assignedToPublicKey?: string;
  assignedToPeerId?: string;
  createdByPublicKey: string;
  createdByPeerId?: string;
  priority?: string;
  rewardSats?: number;
  rewardCurrency?: string;
  dueAt?: number;
};

export function resolveSessionTaskPeerIdsScoped(
  data: CreateSessionTaskInput,
  getParticipantPeerId: (sessionId: string, publicKey: string) => string | undefined,
): CreateSessionTaskInput {
  return {
    ...data,
    assignedToPeerId: data.assignedToPeerId || (
      data.assignedToPublicKey
        ? getParticipantPeerId(data.sessionId, data.assignedToPublicKey)
        : undefined
    ),
    createdByPeerId: data.createdByPeerId || getParticipantPeerId(data.sessionId, data.createdByPublicKey),
  };
}

export function getTaskStatusEventTypeScoped(status: Task["status"] | undefined): "task.completed" | "task.assigned" | undefined {
  if (status === "approved") return "task.completed";
  if (status === "submitted") return "task.assigned";
  return undefined;
}

export function buildTaskCreatedEventPayloadScoped(task: Task): Record<string, unknown> {
  return {
    taskId: task.id,
    sessionId: task.sessionId,
  };
}

export function buildTaskStatusEventPayloadScoped(taskId: string): Record<string, unknown> {
  return { taskId };
}

export function buildTaskStatusEventScoped(
  taskId: string,
  status: Task["status"] | undefined,
): { type: "task.completed" | "task.assigned"; payload: Record<string, unknown> } | undefined {
  const type = getTaskStatusEventTypeScoped(status);
  if (!type) return undefined;
  return {
    type,
    payload: buildTaskStatusEventPayloadScoped(taskId),
  };
}

export function createResolvedSessionTaskScoped(params: {
  data: CreateSessionTaskInput;
  createTask: (data: CreateSessionTaskInput) => Task;
  getParticipantPeerId: (sessionId: string, publicKey: string) => string | undefined;
}): Task {
  return params.createTask(resolveSessionTaskPeerIdsScoped(
    params.data,
    params.getParticipantPeerId,
  ));
}

export async function createSessionTaskForStorageScoped(params: {
  data: CreateSessionTaskInput;
  store: SessionTaskStore;
  getParticipantPeerId: (sessionId: string, publicKey: string) => string | undefined;
  addEvent: (type: "task.created", nodeId: string, data?: Record<string, unknown>) => Promise<unknown>;
  sanitizeTask: (task: Task) => Task;
}): Promise<Task> {
  const task = createResolvedSessionTaskScoped({
    data: params.data,
    createTask: params.store.create.bind(params.store),
    getParticipantPeerId: params.getParticipantPeerId,
  });
  await params.addEvent("task.created", "system", buildTaskCreatedEventPayloadScoped(task));
  return params.sanitizeTask(task);
}

export async function updateSessionTaskForStorageScoped(params: {
  id: string;
  updates: Partial<Task>;
  store: SessionTaskStore;
  addEvent: (type: "task.completed" | "task.assigned", nodeId: string, data?: Record<string, unknown>) => Promise<unknown>;
  sanitizeTask: (task: Task) => Task;
}): Promise<Task | undefined> {
  const task = params.store.update(params.id, params.updates);
  if (!task) return undefined;
  const statusEvent = buildTaskStatusEventScoped(params.id, params.updates.status);
  if (statusEvent) await params.addEvent(statusEvent.type, "system", statusEvent.payload);
  return params.sanitizeTask(task);
}

export async function deleteSessionTaskForStorageScoped(params: {
  id: string;
  store: SessionTaskStore;
}): Promise<Task | undefined> {
  return params.store.delete(params.id);
}

export class SessionTaskStore {
  private tasks: Map<string, Task> = new Map();

  create(data: CreateSessionTaskInput): Task {
    const task: Task = {
      id: randomUUID(),
      sessionId: data.sessionId,
      title: data.title,
      description: data.description,
      assignedToPublicKey: data.assignedToPublicKey,
      assignedToPeerId: data.assignedToPeerId,
      createdByPublicKey: data.createdByPublicKey,
      createdByPeerId: data.createdByPeerId,
      status: "open",
      priority: (data.priority as any) || "medium",
      rewardSats: data.rewardSats,
      rewardCurrency: (data.rewardCurrency as any) || undefined,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      dueAt: data.dueAt,
      comments: [],
      attachments: [],
    };
    this.tasks.set(task.id, task);
    return task;
  }

  get(id: string): Task | undefined {
    return this.tasks.get(id);
  }

  listForSession(sessionId: string): Task[] {
    return Array.from(this.tasks.values())
      .filter((task) => task.sessionId === sessionId)
      .sort((a, b) => b.createdAt - a.createdAt);
  }

  values(): IterableIterator<Task> {
    return this.tasks.values();
  }

  update(id: string, updates: Partial<Task>): Task | undefined {
    const task = this.tasks.get(id);
    if (!task) return undefined;
    Object.assign(task, { ...updates, updatedAt: Date.now() });
    return task;
  }

  delete(id: string): Task | undefined {
    const task = this.tasks.get(id);
    if (!task) return undefined;
    this.tasks.delete(id);
    return task;
  }

  deleteSession(sessionId: string): number {
    let removed = 0;
    this.tasks.forEach((task, taskId) => {
      if (task.sessionId !== sessionId) return;
      this.tasks.delete(taskId);
      removed += 1;
    });
    return removed;
  }

  purgePublicKey(publicKey: string, normalizePublicKey: (value: string) => string): number {
    const normalized = normalizePublicKey(publicKey);
    let removed = 0;
    this.tasks.forEach((task) => {
      if (
        normalizePublicKey(String(task.createdByPublicKey || "")) === normalized ||
        normalizePublicKey(String(task.assignedToPublicKey || "")) === normalized
      ) {
        this.tasks.delete(task.id);
        removed += 1;
      }
    });
    return removed;
  }

  deleteParticipantTasks(sessionId: string, publicKey: string): number {
    let removed = 0;
    this.tasks.forEach((task, taskId) => {
      if (task.sessionId !== sessionId) return;
      if (task.createdByPublicKey === publicKey || task.assignedToPublicKey === publicKey) {
        this.tasks.delete(taskId);
        removed += 1;
      }
    });
    return removed;
  }

  cancelAll(): void {
    this.tasks.forEach((task) => {
      task.status = "cancelled";
    });
  }

  exportSnapshot(): Array<[string, Task]> {
    return Array.from(this.tasks.entries());
  }

  importSnapshot(tasks: Map<string, Task>): void {
    this.tasks = tasks;
  }

  clear(): void {
    this.tasks.clear();
  }
}
