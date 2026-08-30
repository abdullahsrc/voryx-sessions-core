import type { Request, Response } from "express";
import { getSessionCreatorPeerIdScoped, isSessionCreatorByPeerIdScoped } from "../storage/session-access-policy";

type SessionAccessStorage = {
  getSession: (sessionId: string) => Promise<any | null | undefined>;
  getSessionParticipantPeerId: (sessionId: string, publicKey: string) => Promise<string | null | undefined>;
  getSessionPassphraseState: (
    sessionId: string,
    publicKey: string,
  ) => Promise<{ hasPassphrase?: boolean; hasGrant?: boolean }>;
};

type CreateSessionAccessGuardsOptions = {
  storage: SessionAccessStorage;
};

export function createSessionAccessGuards(options: CreateSessionAccessGuardsOptions) {
  const { storage } = options;

  const requireSessionParticipant = async (
    req: Request,
    res: Response,
    sessionId: string,
    publicKey: string,
  ) => {
    const session = await storage.getSession(sessionId);
    if (!session) {
      res.status(404).json({ success: false, error: "Session not found" });
      return null;
    }
    const participantPeerId = await storage.getSessionParticipantPeerId(sessionId, publicKey);
    if (!participantPeerId) {
      res.status(403).json({ success: false, error: "Session access denied" });
      return null;
    }
    return session;
  };

  const requireSessionMessageAccess = async (
    req: Request,
    res: Response,
    sessionId: string,
    publicKey: string,
  ) => {
    const session = await requireSessionParticipant(req, res, sessionId, publicKey);
    if (!session) return null;
    const requesterPeerId = await storage.getSessionParticipantPeerId(sessionId, publicKey);
    if (requesterPeerId && isSessionCreatorByPeerIdScoped(session, requesterPeerId)) return session;
    const state = await storage.getSessionPassphraseState(sessionId, publicKey);
    if (!state.hasPassphrase || !state.hasGrant) {
      res.status(423).json({
        success: false,
        error: "Message access locked until creator passphrase is granted",
      });
      return null;
    }
    return session;
  };

  const requireSessionCreator = async (
    req: Request,
    res: Response,
    sessionId: string,
    publicKey: string,
  ) => {
    const session = await requireSessionParticipant(req, res, sessionId, publicKey);
    if (!session) return null;
    const requesterPeerId = await storage.getSessionParticipantPeerId(sessionId, publicKey);
    const creatorPeerId = getSessionCreatorPeerIdScoped(session);
    if (!requesterPeerId || !creatorPeerId || creatorPeerId !== requesterPeerId) {
      res.status(403).json({ success: false, error: "Only creator can perform this action" });
      return null;
    }
    return session;
  };

  return {
    requireSessionParticipant,
    requireSessionMessageAccess,
    requireSessionCreator,
  };
}
