import { useState, useEffect } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import { useWebSocket } from '../lib/hooks/useWebSocket';
import api from '../lib/api';

export default function CallManager() {
  const [phoneNumber, setPhoneNumber] = useState('');

  const { data: calls, refetch } = useQuery(['calls'], () =>
    api.get('/api/calls').then(res => res.data)
  );

  useWebSocket('wss://ajingolik.fun/ws', {
    onMessage: (data) => {
      if (data.type === 'call_status_update') {
        refetch();
      }
    },
    onError: (error) => {
      console.error('WebSocket error:', error);
      toast.error('Lost connection to server');
    }
  });

  const makeCall = useMutation(
    (number) => api.post('/api/outbound-call', { phone_number: number }),
    {
      onSuccess: () => {
        toast.success('Call initiated successfully');
        setPhoneNumber('');
        refetch();
      },
      onError: (error) => {
        toast.error(error.response?.data?.message || 'Failed to initiate call');
      }
    }
  );

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!phoneNumber) {
      toast.error('Please enter a phone number');
      return;
    }
    makeCall.mutate(phoneNumber);
  };

  return (
    <div className="space-y-6">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="phoneNumber" className="block text-sm font-medium text-gray-700">
            Phone Number
          </label>
          <div className="mt-1 flex rounded-md shadow-sm">
            <input
              type="tel"
              name="phoneNumber"
              id="phoneNumber"
              className="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
              placeholder="+1234567890"
              value={phoneNumber}
              onChange={(e) => setPhoneNumber(e.target.value)}
            />
            <button
              type="submit"
              disabled={makeCall.isLoading}
              className="ml-3 inline-flex justify-center rounded-md border border-transparent bg-indigo-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:opacity-50"
            >
              {makeCall.isLoading ? 'Calling...' : 'Call'}
            </button>
          </div>
        </div>
      </form>

      <div className="bg-white shadow overflow-hidden sm:rounded-md">
        <ul className="divide-y divide-gray-200">
          {calls?.map((call) => (
            <li key={call.id}>
              <div className="px-4 py-4 sm:px-6">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium text-indigo-600 truncate">
                    {call.phone_number}
                  </p>
                  <div className="ml-2 flex-shrink-0 flex">
                    <p className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                      call.status === 'completed' ? 'bg-green-100 text-green-800' : 
                      call.status === 'failed' ? 'bg-red-100 text-red-800' : 
                      'bg-yellow-100 text-yellow-800'
                    }`}>
                      {call.status}
                    </p>
                  </div>
                </div>
                <div className="mt-2 sm:flex sm:justify-between">
                  <div className="sm:flex">
                    <p className="flex items-center text-sm text-gray-500">
                      Duration: {call.duration}s
                    </p>
                  </div>
                  <div className="mt-2 flex items-center text-sm text-gray-500 sm:mt-0">
                    <p>
                      {new Date(call.created_at).toLocaleString()}
                    </p>
                  </div>
                </div>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
