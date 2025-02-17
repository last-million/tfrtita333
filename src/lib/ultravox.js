import axios from 'axios'

const ULTRAVOX_API_URL = import.meta.env.VITE_ULTRAVOX_API_URL
const ULTRAVOX_API_KEY = import.meta.env.VITE_ULTRAVOX_API_KEY

class UltravoxClient {
  constructor() {
    this.client = axios.create({
      baseURL: ULTRAVOX_API_URL,
      headers: {
        'X-API-Key': ULTRAVOX_API_KEY,
        'Content-Type': 'application/json'
      }
    })
  }

  async createCall(phoneNumber, systemPrompt) {
    try {
      const response = await this.client.post('/calls', {
        systemPrompt,
        model: "fixie-ai/ultravox-70B",
        voice: "Mark",
        medium: {
          twilio: {}
        },
        firstSpeaker: "FIRST_SPEAKER_AGENT",
        recordingEnabled: true,
        selectedTools: [
          {
            temporaryTool: {
              modelToolName: "detectIntent",
              description: "Detect if the customer is interested or not based on their responses",
              dynamicParameters: [
                {
                  name: "conversation",
                  location: "PARAMETER_LOCATION_BODY",
                  schema: {
                    type: "string",
                    description: "The conversation transcript"
                  },
                  required: true
                }
              ],
              client: {}
            }
          }
        ]
      })
      return response.data
    } catch (error) {
      console.error('Error creating call:', error)
      throw error
    }
  }

  async getCallHistory(params = {}) {
    try {
      const response = await this.client.get('/calls', { params })
      return response.data
    } catch (error) {
      console.error('Error fetching call history:', error)
      throw error
    }
  }

  async getCallDetails(callId) {
    try {
      const response = await this.client.get(`/calls/${callId}`)
      return response.data
    } catch (error) {
      console.error('Error fetching call details:', error)
      throw error
    }
  }

  async getCallRecording(callId) {
    try {
      const response = await this.client.get(`/calls/${callId}/recording`)
      return response.data
    } catch (error) {
      console.error('Error fetching call recording:', error)
      throw error
    }
  }

  async getCallTranscript(callId) {
    try {
      const response = await this.client.get(`/calls/${callId}/messages`)
      return response.data
    } catch (error) {
      console.error('Error fetching call transcript:', error)
      throw error
    }
  }
}

export const ultravoxClient = new UltravoxClient()
