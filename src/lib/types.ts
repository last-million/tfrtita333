export interface Call {
  callId: string;
  created: string;
  ended?: string;
  endReason?: 'unjoined' | 'hangup' | 'agent_hangup' | 'timeout' | 'connection_error';
  phone_number: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  duration: number;
  intent?: 'interested' | 'not_interested';
  shortSummary?: string;
  recording_url?: string;
}

export interface CallStats {
  totalCalls: number;
  completedCalls: number;
  successRate: string;
  callVolume: Array<{
    date: string;
    calls: number;
  }>;
}

export interface CallFilters {
  dateRange: {
    start: string;
    end: string;
  };
  status?: string;
  intent?: string;
  searchTerm?: string;
}

export interface Message {
  role: 'MESSAGE_ROLE_AGENT' | 'MESSAGE_ROLE_USER';
  text: string;
  callStageMessageIndex: number;
  medium: 'MESSAGE_MEDIUM_VOICE' | 'MESSAGE_MEDIUM_TEXT';
}
