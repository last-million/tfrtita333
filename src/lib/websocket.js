class WebSocketClient {
  constructor(url, options = {}) {
    this.url = url;
    this.options = {
      reconnectAttempts: 10, // Increased reconnect attempts
      reconnectDelay: 5000, // Increased reconnect delay
      onMessage: () => {},
      onError: (error) => {
        console.error('WebSocket error:', error);
      },
      onClose: (event) => {
        console.log('WebSocket closed:', event);
      },
      onOpen: () => {
        console.log('WebSocket connected');
      },
      ...options
    };
    this.ws = null;
    this.reconnectCount = 0;
    this.isConnecting = false;
  }

  connect() {
    if (this.isConnecting) return;
    this.isConnecting = true;

    try {
      this.ws = new WebSocket(this.url);
      this.ws.onmessage = this.handleMessage.bind(this);
      this.ws.onerror = this.handleError.bind(this);
      this.ws.onclose = this.handleClose.bind(this);
      this.ws.onopen = this.handleOpen.bind(this);
    } catch (error) {
      console.error('WebSocket connection error:', error);
      this.handleError(error);
    }
  }

  handleMessage(event) {
    try {
      const data = JSON.parse(event.data);
      this.options.onMessage(data);
    } catch (error) {
      console.error('WebSocket message parsing error:', error);
      this.options.onError(error);
    }
  }

  handleError(error) {
    console.error('WebSocket error:', error);
    this.options.onError(error);
  }

  handleClose(event) {
    this.isConnecting = false;
    if (typeof this.options.onClose === 'function') {
      this.options.onClose(event);
    }

    if (this.reconnectCount < this.options.reconnectAttempts) {
      console.log(`WebSocket reconnect attempt ${this.reconnectCount + 1}`);
      setTimeout(() => {
        this.reconnectCount++;
        this.connect();
      }, this.options.reconnectDelay);
    } else {
      console.error('WebSocket reconnection attempts exhausted.');
    }
  }

  handleOpen() {
    this.isConnecting = false;
    this.reconnectCount = 0;
    this.options.onOpen();
  }

  send(data) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      try {
        this.ws.send(JSON.stringify(data));
      } catch (error) {
        console.error('WebSocket send error:', error);
        this.options.onError(error);
      }
    } else {
      console.error('WebSocket is not open');
      this.options.onError(new Error('WebSocket is not open'));
    }
  }

  close() {
    if (this.ws) {
      this.ws.close();
    }
  }
}

export default WebSocketClient;
