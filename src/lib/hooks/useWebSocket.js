import { useEffect, useRef, useCallback } from 'react';
import WebSocketClient from '../websocket';

export function useWebSocket(url, options = {}) {
  const wsRef = useRef(null);
  
  const handleMessage = useCallback((data) => {
    switch (data.event) {
      case 'call_started':
        options.onCallStarted?.(data);
        break;
      case 'call_ended':
        options.onCallEnded?.(data);
        break;
      case 'transcript_updated':
        options.onTranscriptUpdated?.(data);
        break;
      default:
        console.warn('Unknown WebSocket event:', data);
    }
  }, [options]);

  useEffect(() => {
    console.log('WebSocket URL:', url); // Log the WebSocket URL

    wsRef.current = new WebSocketClient(url, {
      onMessage: handleMessage,
      onError: (error) => {
        console.error('WebSocket error:', error);
        options.onError?.(error);
      },
      onClose: (event) => {
        console.log('WebSocket closed:', event); // Log close event
        options.onClose?.(event);
      },
      onOpen: () => {
        console.log('WebSocket connected'); // Log connection event
        options.onOpen?.();
      }
    });

    wsRef.current.connect();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [url, handleMessage, options]);

  const sendMessage = useCallback((data) => {
    if (wsRef.current) {
      wsRef.current.send(data);
    }
  }, []);

  return { sendMessage };
}
