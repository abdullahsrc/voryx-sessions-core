import { z } from "zod";



export const KeyPermissions = z.enum([
  "session.create",
  "session.join",
  "session.view",
  "session.write",
  "session.file",
  "session.voice",
  "session.task",
  "matching.request",
]);

export type KeyPermission = z.infer<typeof KeyPermissions>;


export const ephemeralKeySchema = z.object({
  id: z.string(),
  publicKey: z.string(),
  privateKey: z.string().optional(),
  kxPublicKey: z.string().optional(),
  kxPrivateKey: z.string().optional(),
  permissions: z.array(KeyPermissions),
  ttl: z.number(),
  createdAt: z.number(),
  expiresAt: z.number(),
  isActive: z.boolean(),
  nodeId: z.string().optional(),
  label: z.string().optional(),
  domain: z.string().optional(),
});

export type EphemeralKey = z.infer<typeof ephemeralKeySchema>;

export const createKeySchema = z.object({
  ttlMinutes: z.coerce.number().int().min(1).max(5256000),
  permissions: z.array(KeyPermissions).min(1),
  publicKey: z
    .string()
    .trim()
    .regex(/^[a-f0-9]{64}$/i, "publicKey must be 32-byte hex")
    .optional(),
  kxPublicKey: z
    .string()
    .trim()
    .regex(/^[a-f0-9]{64}$/i, "kxPublicKey must be 32-byte hex")
    .optional(),
  label: z
    .string()
    .trim()
    .max(64)
    .regex(/^[a-zA-Z0-9 _.-]*$/, "label contains unsupported characters")
    .optional(),
  domain: z
    .string()
    .trim()
    .max(96)
    .regex(/^[a-zA-Z0-9_., +.-]*$/, "domain contains unsupported characters")
    .optional(),
});

export type CreateKeyInput = z.infer<typeof createKeySchema>;

export const SessionStatus = z.enum([
  "pending",
  "active",
  "expiring_soon",
  "expired",
  "terminated",
]);

export type SessionStatusType = z.infer<typeof SessionStatus>;



export const TaskStatus = z.enum([
  "open",
  "in_progress",
  "submitted",
  "approved",
  "rejected",
  "cancelled",
]);
export type TaskStatusType = z.infer<typeof TaskStatus>;

export const TaskPriority = z.enum(["low", "medium", "high", "critical"]);
export type TaskPriorityType = z.infer<typeof TaskPriority>;

export const TaskRewardCurrency = z.enum([
  "USD",
  "EUR",
  "GBP",
  "JPY",
  "CNY",
  "CHF",
  "CAD",
  "AUD",
  "INR",
  "AED",
  "BTC",
  "ETH",
  "USDT",
  "BNB",
  "SOL",
]);
export type TaskRewardCurrencyType = z.infer<typeof TaskRewardCurrency>;

export const taskSchema = z.object({
  id: z.string(),
  sessionId: z.string(),
  title: z.string(),
  description: z.string(),
  assignedToPeerId: z.string().optional(),
  assignedToPublicKey: z.string().optional(), // Legacy compatibility field
  createdByPeerId: z.string().optional(),
  createdByPublicKey: z.string(), // Legacy compatibility field
  status: TaskStatus,
  priority: TaskPriority,
  rewardSats: z.number().optional(),
  rewardCurrency: TaskRewardCurrency.optional(),
  createdAt: z.number(),
  updatedAt: z.number(),
  dueAt: z.number().optional(),
  completedAt: z.number().optional(),
  attachments: z.array(z.object({
    name: z.string(),
    hash: z.string(), 
    encryptedUrl: z.string().optional(),
  })).optional(),
  comments: z.array(z.object({
    id: z.string(),
    authorPeerId: z.string().optional(),
    authorPublicKey: z.string().optional(), // Legacy compatibility field
    content: z.string(), 
    timestamp: z.number(),
  })).optional(),
});
export type Task = z.infer<typeof taskSchema>;

export const createTaskSchema = z.object({
  sessionId: z.string(),
  title: z.string().min(1).max(200),
  description: z.string().max(2000),
  assignedToPeerId: z.string().optional(),
  assignedToPublicKey: z.string().optional(), // Legacy compatibility field
  createdByPeerId: z.string().optional(),
  createdByPublicKey: z.string().optional(), // Legacy compatibility field
  priority: TaskPriority.default("medium"),
  rewardSats: z.number().min(0).optional(),
  rewardCurrency: TaskRewardCurrency.optional(),
  dueAt: z.number().optional(),
});
export type CreateTaskInput = z.infer<typeof createTaskSchema>;



export const MessageType = z.enum([
  "text",
  "system",
  "encrypted",
  "file",
  "voice_note",
  "voice_started",
  "voice_ended",
  "task_assigned",
]);
export type MessageTypeEnum = z.infer<typeof MessageType>;

export const chatMessageSchema = z.object({
  id: z.string(),
  sessionId: z.string(),
  senderScopeId: z.string().optional(),
  senderSessionCryptoPublicKey: z.string().optional(), // Session-ephemeral identity groundwork; transport may omit until v1 rollout
  senderSessionCryptoKeyId: z.string().optional(), // Session-ephemeral identity groundwork; transport may omit until v1 rollout
  senderPublicKey: z.string(), // Legacy compatibility field; transport should prefer senderScopeId
  senderLabel: z.string().optional(),
  type: MessageType,
  content: z.string(), 
  encryptedContent: z.string().optional(), 
  disappearAfterReadSeconds: z.number().int().min(0).max(3600).optional(),
  disappearAfterSeconds: z.number().int().min(0).max(3600).optional(),
  traceHash: z.string().optional(),
  prevTraceHash: z.string().optional(),
  timestamp: z.number(),
  signature: z.string(), 
  replyToId: z.string().optional(),
  attachmentArtifactId: z.string().optional(),
  attachmentArtifactIds: z.array(z.string()).optional(),
  edited: z.boolean().default(false),
  editedAt: z.number().optional(),
});
export type ChatMessage = z.infer<typeof chatMessageSchema>;



export const ParticipantRole = z.enum([
  "creator",
  "provider",
  "observer",
  "arbitrator",
]);
export type ParticipantRoleType = z.infer<typeof ParticipantRole>;

export const participantSchema = z.object({
  peerId: z.string().optional(),
  publicKey: z.string(), // Legacy compatibility field; client transport should prefer peerId
  sessionCryptoPublicKey: z.string().optional(), // Session-ephemeral identity groundwork; currently mirrors legacy key material until v1 rollout
  sessionCryptoKeyId: z.string().optional(), // Session-ephemeral identity groundwork; currently mirrors legacy key identity until v1 rollout
  label: z.string().optional(), 
  role: ParticipantRole,
  joinedAt: z.number(),
  isOnline: z.boolean(),
  keyId: z.string().optional(), 
  encryptedContact: z.string().optional(), 
  voiceEnabled: z.boolean().default(false),
  revenueShare: z.number().optional(), 
});
export type Participant = z.infer<typeof participantSchema>;



export const sessionSchema = z.object({
  id: z.string(),
  participants: z.array(z.string()), // Legacy compatibility field; client transport should prefer participantPeerIds/participantDetails.peerId
  participantPeerIds: z.array(z.string()).optional(),
  sessionIdentityMode: z.enum(["legacy_v0", "session_ephemeral_v1"]).optional(),
  creatorPeerId: z.string().optional(),
  participantCount: z.number().int().min(0).optional(),
  participantDetails: z.array(participantSchema).optional(),
  status: SessionStatus,
  startTime: z.number(),
  duration: z.number(),
  expiresAt: z.number(),
  nodeIds: z.array(z.string()),
  encryptedMetadata: z.string().optional(),
  name: z.string().optional(),
  domain: z.string().optional(), 
  description: z.string().optional(),
  maxParticipants: z.number().int().min(0).default(10),
  isPrivate: z.boolean().default(true),
  encryptionPublicKey: z.string().optional(), 
  voiceChannelActive: z.boolean().default(false),
  sessionAccess: z.object({
    bootstrapPath: z.string().optional(),
    expiresAt: z.number().optional(),
  }).optional(),
  mailboxBootstrap: z.object({
    messagePlaneTokenPath: z.string().optional(),
    controlPlaneTokenPath: z.string().optional(),
    expiresAt: z.number().optional(),
  }).optional(),
  selfSessionCryptoIdentity: z.object({
    publicKey: z.string().optional(),
    keyId: z.string().optional(),
  }).optional(),
});

export type Session = z.infer<typeof sessionSchema>;

export const createSessionSchema = z.object({
  // Kept optional for backward compatibility. The server derives session lifetime
  // from the creator key expiry, not from client-provided duration.
  durationMinutes: z.coerce.number().int().min(0).max(5256000).optional(),
  keyId: z.string(),
  name: z
    .string()
    .trim()
    .max(64)
    .regex(/^[a-zA-Z0-9 _.-]*$/, "name contains unsupported characters")
    .optional(),
  domain: z.string().optional(),
  description: z.string().optional(),
  maxParticipants: z.number().int().min(0).default(10),
  isPrivate: z.boolean().optional(),
});

export type CreateSessionInput = z.infer<typeof createSessionSchema>;

export const wsMessageSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("chat"), message: chatMessageSchema }),
  z.object({ type: z.literal("message_updated"), message: chatMessageSchema }),
  z.object({ type: z.literal("message_deleted"), messageId: z.string(), sessionId: z.string().optional() }),
  z.object({ type: z.literal("participant_joined"), participant: participantSchema, sessionId: z.string().optional() }),
  z.object({
    type: z.literal("participant_left"),
    publicKey: z.string().optional(),
    peerId: z.string().optional(),
    sessionId: z.string().optional(),
  }),
  z.object({ type: z.literal("task_updated"), task: taskSchema }),
  z.object({ type: z.literal("task_deleted"), taskId: z.string(), sessionId: z.string().optional() }),
  z.object({ type: z.literal("subscribe"), sessionId: z.string(), keyId: z.string() }),
  z.object({ type: z.literal("ping") }),
  z.object({ type: z.literal("pong") }),
]);
export type WsMessage = z.infer<typeof wsMessageSchema>;



export const NodeType = z.enum([
  "bootstrap",
  "session",
  "relay",
  "policy",
  "proof",
]);
export type NodeTypeEnum = z.infer<typeof NodeType>;

export const NodeHealth = z.enum(["healthy", "degraded", "offline"]);
export type NodeHealthType = z.infer<typeof NodeHealth>;

export const GeoLocation = z.enum([
  "us-east",
  "us-west",
  "eu-west",
  "eu-central",
  "asia-pacific",
  "south-america",
]);
export type GeoLocationType = z.infer<typeof GeoLocation>;

export const nodeSchema = z.object({
  id: z.string(),
  type: NodeType,
  location: GeoLocation,
  health: NodeHealth,
  activeSessions: z.number(),
  load: z.number(),
  lastHeartbeat: z.number(),
  connectedNodes: z.array(z.string()),
});
export type Node = z.infer<typeof nodeSchema>;



export const EventType = z.enum([
  "key.created",
  "key.extended",
  "key.killed",
  "key.expired",
  "session.created",
  "session.joined",
  "session.join_request_created",
  "session.left",
  "session.expired",
  "session.terminated",
  "node.connected",
  "node.disconnected",
  "match.requested",
  "match.found",
  "task.created",
  "task.assigned",
  "task.completed",
  "voice.started",
  "voice.ended",
]);
export type EventTypeEnum = z.infer<typeof EventType>;

export const systemEventSchema = z.object({
  id: z.string(),
  type: EventType,
  timestamp: z.number(),
  nodeId: z.string(),
  data: z.record(z.unknown()).optional(),
  signature: z.string(),
});
export type SystemEvent = z.infer<typeof systemEventSchema>;



export const AttributeType = z.enum([
  "category",
  "skill",
  "budget_range",
  "duration_range",
  "availability",
  "location",
  "language",
  "certification",
  "experience_level",
]);
export type AttributeTypeEnum = z.infer<typeof AttributeType>;

export const CategoryValue = z.enum([
  "development", "design", "marketing", "writing", "consulting",
  "data_science", "devops", "security", "support", "other"
]);
export type CategoryValueType = z.infer<typeof CategoryValue>;

export const SkillValue = z.enum([
  "react", "typescript", "nodejs", "python", "go", "rust", "java",
  "figma", "photoshop", "illustrator", "sketch",
  "aws", "gcp", "azure", "docker", "kubernetes",
  "postgresql", "mongodb", "redis", "graphql", "rest",
  "machine_learning", "data_analysis", "blockchain", "web3",
  "content_writing", "copywriting", "seo", "social_media",
  "project_management", "agile", "scrum", "leadership",
  "other"
]);
export type SkillValueType = z.infer<typeof SkillValue>;

export const LocationValue = z.enum([
  "us_east", "us_west", "us_central",
  "eu_west", "eu_central", "eu_east",
  "asia_pacific", "asia_south", "asia_east",
  "south_america", "africa", "oceania",
  "remote", "any"
]);
export type LocationValueType = z.infer<typeof LocationValue>;

export const LanguageValue = z.enum([
  "english", "spanish", "french", "german", "portuguese",
  "chinese", "japanese", "korean", "hindi", "arabic",
  "russian", "italian", "dutch", "other"
]);
export type LanguageValueType = z.infer<typeof LanguageValue>;

export const CertificationValue = z.enum([
  "aws_certified", "gcp_certified", "azure_certified",
  "pmp", "scrum_master", "kubernetes_certified",
  "security_plus", "cissp", "ccna",
  "none", "other"
]);
export type CertificationValueType = z.infer<typeof CertificationValue>;

export const ExperienceLevelValue = z.enum([
  "junior", "mid", "senior", "lead", "principal"
]);
export type ExperienceLevelValueType = z.infer<typeof ExperienceLevelValue>;

export const RangeSchema = z.object({
  min: z.number().int().min(0),
  max: z.number().int().min(0),
}).refine(data => data.max >= data.min, { message: "max must be >= min" });
export type Range = z.infer<typeof RangeSchema>;

export const CategoryAttributeSchema = z.object({
  type: z.literal("category"),
  value: CategoryValue,
  weight: z.number().min(0).max(1).default(1),
  required: z.boolean().default(true),
});
export const SkillAttributeSchema = z.object({
  type: z.literal("skill"),
  value: z.array(z.string().min(1).max(64)).min(1).max(20),
  weight: z.number().min(0).max(1).default(1),
  required: z.boolean().default(true),
});
export const BudgetRangeAttributeSchema = z.object({
  type: z.literal("budget_range"),
  value: RangeSchema,
  weight: z.number().min(0).max(1).default(1),
  required: z.boolean().default(true),
});
export const DurationRangeAttributeSchema = z.object({
  type: z.literal("duration_range"),
  value: RangeSchema,
  weight: z.number().min(0).max(1).default(1),
  required: z.boolean().default(true),
});
export const AvailabilityAttributeSchema = z.object({
  type: z.literal("availability"),
  value: RangeSchema,
  weight: z.number().min(0).max(1).default(1),
  required: z.boolean().default(true),
});
export const LocationAttributeSchema = z.object({
  type: z.literal("location"),
  value: LocationValue,
  weight: z.number().min(0).max(1).default(1),
  required: z.boolean().default(true),
});
export const LanguageAttributeSchema = z.object({
  type: z.literal("language"),
  value: z.array(LanguageValue).min(1).max(5),
  weight: z.number().min(0).max(1).default(1),
  required: z.boolean().default(true),
});
export const CertificationAttributeSchema = z.object({
  type: z.literal("certification"),
  value: z.array(CertificationValue).min(0).max(5),
  weight: z.number().min(0).max(1).default(1),
  required: z.boolean().default(true),
});
export const ExperienceAttributeSchema = z.object({
  type: z.literal("experience_level"),
  value: ExperienceLevelValue,
  weight: z.number().min(0).max(1).default(1),
  required: z.boolean().default(true),
});

export const AttributeSchema = z.discriminatedUnion("type", [
  CategoryAttributeSchema,
  SkillAttributeSchema,
  BudgetRangeAttributeSchema,
  DurationRangeAttributeSchema,
  AvailabilityAttributeSchema,
  LocationAttributeSchema,
  LanguageAttributeSchema,
  CertificationAttributeSchema,
  ExperienceAttributeSchema,
]);
export type Attribute = z.infer<typeof AttributeSchema>;

export const ProtocolConstraintKey = z.enum([
  "min_rating",
  "verified_only",
  "same_region",
  "timezone_overlap",
]);
export type ProtocolConstraintKeyType = z.infer<typeof ProtocolConstraintKey>;

export const ProtocolConstraintSchema = z.object({
  min_rating: z.number().min(0).max(100).optional(),
  verified_only: z.boolean().optional(),
  same_region: z.boolean().optional(),
  timezone_overlap: z.number().min(0).max(24).optional(),
});
export type ProtocolConstraint = z.infer<typeof ProtocolConstraintSchema>;

export const IntentSchema = z.object({
  id: z.string(),
  commitment: z.string(),
  type: z.literal("demand"),
  attributes: z.array(AttributeSchema),
  constraints: ProtocolConstraintSchema,
  preferenceHash: z.string().optional(),
  ttlSeconds: z.number().min(60).max(86400),
  createdAt: z.number(),
  expiresAt: z.number(),
  signature: z.string(),
  publicKey: z.string(),
  status: z.enum(["active", "matched", "expired", "cancelled"]),
});
export type Intent = z.infer<typeof IntentSchema>;

export const CapabilitySchema = z.object({
  id: z.string(),
  commitment: z.string(),
  type: z.literal("supply"),
  attributes: z.array(AttributeSchema),
  constraints: ProtocolConstraintSchema,
  preferenceHash: z.string().optional(),
  ttlSeconds: z.number().min(60).max(86400),
  createdAt: z.number(),
  expiresAt: z.number(),
  signature: z.string(),
  publicKey: z.string(),
  status: z.enum(["active", "matched", "expired", "cancelled"]),
});
export type Capability = z.infer<typeof CapabilitySchema>;

export const MatchProposalSchema = z.object({
  id: z.string(),
  intentId: z.string(),
  capabilityId: z.string(),
  intentCommitment: z.string(),
  capabilityCommitment: z.string(),
  compatibilityScore: z.number().min(0).max(1),
  satisfiedConstraints: z.array(z.string()),
  unsatisfiedConstraints: z.array(z.string()),
  proposedBy: z.string(),
  timestamp: z.number(),
  signature: z.string(),
});
export type MatchProposal = z.infer<typeof MatchProposalSchema>;

export const MatchVoteSchema = z.object({
  proposalId: z.string(),
  nodeId: z.string(),
  vote: z.enum(["approve", "reject", "abstain"]),
  verificationProof: z.string(),
  reason: z.string().optional(),
  signature: z.string(),
  timestamp: z.number(),
});
export type MatchVote = z.infer<typeof MatchVoteSchema>;

export const MatchQuorumCertificateSchema = z.object({
  proposalId: z.string(),
  intentId: z.string(),
  capabilityId: z.string(),
  approved: z.boolean(),
  totalVotes: z.number(),
  approveVotes: z.number(),
  rejectVotes: z.number(),
  quorumReached: z.boolean(),
  votes: z.array(MatchVoteSchema),
  issuedAt: z.number(),
  expiresAt: z.number(),
  certificateHash: z.string(),
  issuerSignature: z.string(),
});
export type MatchQuorumCertificate = z.infer<typeof MatchQuorumCertificateSchema>;

export const MatchResultSchema = z.object({
  id: z.string(),
  intentId: z.string(),
  capabilityId: z.string(),
  intentPublicKey: z.string().optional(),
  capabilityPublicKey: z.string().optional(),
  intentLabel: z.string().optional(),
  capabilityLabel: z.string().optional(),
  domain: z.string().optional(),
  score: z.number().optional(),
  reasons: z.array(z.string()).optional(),
  status: z.enum(["pending_quorum", "approved", "rejected", "expired"]),
  quorumCertificate: MatchQuorumCertificateSchema.optional(),
  sessionId: z.string().optional(),
  createdAt: z.number(),
  finalizedAt: z.number().optional(),
});
export type MatchResult = z.infer<typeof MatchResultSchema>;

export const createIntentSchema = z.object({
  attributes: z.array(AttributeSchema).min(1).max(10),
  constraints: ProtocolConstraintSchema.optional(),
  ttlMinutes: z.number().min(1).max(1440).default(60),
  preferenceHash: z.string().optional(),
});
export type CreateIntentInput = z.infer<typeof createIntentSchema>;

export const createCapabilitySchema = z.object({
  attributes: z.array(AttributeSchema).min(1).max(10),
  constraints: ProtocolConstraintSchema.optional(),
  ttlMinutes: z.number().min(1).max(1440).default(60),
  preferenceHash: z.string().optional(),
});
export type CreateCapabilityInput = z.infer<typeof createCapabilitySchema>;

export const matchRequestSchema = z.object({
  id: z.string(),
  keyId: z.string(),
  criteria: z.record(z.unknown()),
  status: z.enum(["pending", "matched", "expired", "cancelled"]),
  createdAt: z.number(),
  expiresAt: z.number(),
});
export type MatchRequest = z.infer<typeof matchRequestSchema>;


export const dashboardStatsSchema = z.object({
  activeKeys: z.number(),
  activeSessions: z.number(),
  totalNodes: z.number(),
  healthyNodes: z.number(),
  recentEvents: z.number(),
  totalTasks: z.number(),
  activeTasks: z.number(),
});
export type DashboardStats = z.infer<typeof dashboardStatsSchema>;

export const apiResponseSchema = <T extends z.ZodType>(dataSchema: T) =>
  z.object({
    success: z.boolean(),
    data: dataSchema.optional(),
    error: z.string().optional(),
  });

export type InsertUser = { username: string; password: string };
export type User = { id: string; username: string; password: string };
