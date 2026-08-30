import type { Request, Response } from "express";

export type VerifiedKeyAuth = {
  keyId: string;
  publicKey: string;
  key: {
    id?: string;
    publicKey?: string;
    isActive?: boolean;
    permissions?: string[];
    [key: string]: unknown;
  };
};

export type RouteHandlerResult<T = unknown> = Promise<T | null>;

export type RequireVerifiedKey = (
  req: Request,
  res: Response,
) => RouteHandlerResult<VerifiedKeyAuth>;

export type RequireDeletionVerifiedKey = (
  req: Request,
  res: Response,
) => RouteHandlerResult<VerifiedKeyAuth>;

export type RequireSessionPermission = (
  res: Response,
  key: { permissions?: string[] } | undefined,
  permission: string,
  errorMessage: string,
) => boolean;

export type RequireSessionParticipant = (
  req: Request,
  res: Response,
  sessionId: string,
  publicKey: string,
) => Promise<unknown | null>;

export type RequireSessionMessageAccess = (
  req: Request,
  res: Response,
  sessionId: string,
  publicKey: string,
) => Promise<unknown | null>;

export type RequireSessionCreator = (
  req: Request,
  res: Response,
  sessionId: string,
  publicKey: string,
) => Promise<unknown | null>;

export type SendUniformAuthError = (
  res: Response,
  status: number,
  error: string,
  code?: string,
) => Promise<Response | void>;

