/**
 * Public entry point. Re-exports only the surface consumers should use,
 * internal modules under ./crypto, ./transport, ./flow stay un-re-exported
 */

export { MorokBot }                 from './bot.js'
export type { SendArgs, ReplyArgs } from './bot.js'
export type { SendResult }          from './flow/direct.js'
export { SendRejectedError, SendUncertainError } from './flow/direct.js'
export { UploadRejectedError }      from './flow/attachments.js'
export { RateLimiter }              from './ratelimit.js'
export type { RateLimiterOptions }  from './ratelimit.js'
export { BotSessions }              from './sessions.js'
export type { BotSessionsOptions }  from './sessions.js'
export type {
    BotConfig,
    SdkLogger,
    IncomingMessage,
    CommandInvocation,
    Peer,
    ReactionEvent,
    ControlEvent,
    BotStartEvent,
    BotStopEvent,
    ConversationAddedEvent,
    ConversationKickedEvent,
    ConversationType,
    DisconnectInfo,
    MorokbotFile,
    BotCommand,
    BotControl,
    AttachmentInput,
    IncomingAttachment,
    IncomingGallery,
    IncomingGalleryItem,
    VideoNoteShape,
} from './types.js'
