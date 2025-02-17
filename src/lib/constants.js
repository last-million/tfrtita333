export const CALL_STATUSES = {
  PENDING: 'pending',
  IN_PROGRESS: 'in_progress',
  COMPLETED: 'completed',
  FAILED: 'failed'
}

export const CALL_INTENTS = {
  INTERESTED: 'interested',
  NOT_INTERESTED: 'not_interested',
  UNKNOWN: 'unknown'
}

export const API_ENDPOINTS = {
  CALLS: '/api/calls',
  AUTH: '/api/auth',
  USERS: '/api/users',
  STATS: '/api/stats'
}

export const WEBSOCKET_EVENTS = {
  CALL_STARTED: 'call_started',
  CALL_ENDED: 'call_ended',
  TRANSCRIPT_UPDATED: 'transcript_updated',
  INTENT_DETECTED: 'intent_detected',
  ERROR: 'error'
}

export const ERROR_MESSAGES = {
  NETWORK_ERROR: 'Network error occurred. Please check your connection.',
  AUTH_ERROR: 'Authentication failed. Please log in again.',
  VALIDATION_ERROR: 'Please check your input and try again.',
  SERVER_ERROR: 'Server error occurred. Please try again later.',
  WEBSOCKET_ERROR: 'WebSocket connection error. Reconnecting...'
}

export const PAGINATION = {
  DEFAULT_PAGE_SIZE: 10,
  MAX_PAGE_SIZE: 100
}
