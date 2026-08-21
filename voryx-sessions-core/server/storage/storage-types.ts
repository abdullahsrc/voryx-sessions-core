export type DeletionWitness = {
  nodeId: string;
  nodePublicKey: string;
  witnessSignature: string;
  witnessedAt: number;
};

export type DeletionCertificate = {
  certificateId: string;
  intentHash: string;
  deletionRoot: string;
  witnessThreshold: number;
  witnesses: DeletionWitness[];
  scope: string;
  targetId: string;
  requesterCommitment: string;
  issuedAt: number;
  validUntil: number;
  protocolVersion: "v1";
};

export type ReputationAttestation = {
  id: string;
  attesterPublicKey: string;
  attesterIndex?: string;
  subjectPublicKey: string;
  subjectIndex?: string;
  context: "session" | "task" | "manual";
  domain?: string;
  note?: string;
  createdAt: number;
  status: "pending" | "approved" | "rejected";
  responseAt?: number;
};

export type ReputationCreditNote = {
  id: string;
  attestationId: string;
  subjectPublicKey: string;
  subjectIndex?: string;
  attesterPublicKey: string;
  attesterIndex?: string;
  commitmentHash: string;
  nullifier: string;
  witnessSignatures: string[];
  domain?: string;
  issuedAt: number;
  scoreDelta: number;
};

export type ReputationTransfer = {
  id: string;
  fromPublicKey: string;
  fromIndex?: string;
  toPublicKey: string;
  toIndex?: string;
  requestedByPublicKey: string;
  requestedByIndex?: string;
  createdAt: number;
  status: "pending" | "approved" | "rejected";
  responseAt?: number;
  proofHash: string;
};

export type SessionJoinRequest = {
  id: string;
  sessionId: string;
  requesterKeyId: string;
  requesterPublicKey: string;
  requesterLabel?: string;
  status: "pending" | "approved" | "rejected";
  createdAt: number;
  respondedAt?: number;
};

export type SessionInviteCode = {
  sessionId: string;
  codeHash: string;
  createdAt: number;
};

export type SessionMessageMeta = {
  starredIds: string[];
  pinnedIds: string[];
};

export type SessionParticipantIdentity = {
  publicKey: string;
  peerId: string;
  sessionCryptoPublicKey?: string;
  sessionCryptoKeyId?: string;
  label?: string;
  role: string;
  joinedAt: number;
  isOnline: boolean;
  voiceEnabled: boolean;
};

export type KeyFeedbackVote = "approve" | "report";

export type KeyFeedbackEntry = {
  id: string;
  raterPublicKey: string;
  raterIndex?: string;
  targetPublicKey: string;
  targetIndex?: string;
  sessionId: string;
  vote: KeyFeedbackVote;
  createdAt: number;
  updatedAt: number;
};

export type KeyFeedbackSummary = {
  targetPublicKey: string;
  targetPeerId?: string;
  targetRuntimeKey?: string;
  sessionId?: string;
  approveCount: number;
  reportCount: number;
  total: number;
  approveRate: number;
  reportRate: number;
  score: number;
};

export type SecurityAuditRecord = {
  id: string;
  action: string;
  nodeId: string;
  timestamp: number;
  prevHash: string;
  dataHash: string;
  hash: string;
};

export type BlockEnforcementAction = "session_terminated" | "creator_block_member" | "member_block_creator" | "pair_removed";

export type BlockEnforcementResult = {
  sessionId: string;
  action: BlockEnforcementAction;
  removedPublicKeys: string[];
  removedMessageIds: string[];
};

export type PublicFeedbackEntry = {
  id: string;
  message: string;
  createdAt: number;
};

export type PublicFeedbackReaction = "like" | "dislike" | "clear";

export type FileArtifactCleanupPayload = {
  publicKey?: string;
  sessionId?: string;
  artifactId?: string;
  reason: string;
};

export type FileArtifactLinkPayload = {
  artifactId: string;
  messageId: string;
  sessionId: string;
  senderPublicKey: string;
};

export type KeyPurgeLifecyclePayload = {
  publicKey: string;
  keyIds: string[];
  reason: "expired" | "removed" | "orphaned";
  creatorSessionIds: string[];
  participantSessionIds: string[];
  removedMessageIdsBySession: Record<string, string[]>;
};
