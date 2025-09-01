'use client';

import { useAuth } from '../contexts/AuthContext';
import { LoginForm } from '../components/LoginForm';
import { Dashboard } from '../components/Dashboard';

export default function Home() {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return user ? <Dashboard /> : <LoginForm onToggleMode={() => {}} />;
}
