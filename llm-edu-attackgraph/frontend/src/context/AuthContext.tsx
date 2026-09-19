import React, { createContext, useContext, useState, useEffect } from 'react';
import { apiClient } from '../api/client';
import { LoginModal } from '../components/LoginModal';

export interface AuthUser {
  id: string;
  email: string;
  role: string;
}

interface AuthContextType {
  user: AuthUser | null;
  token: string | null;
  isAdmin: boolean;
  isChecking: boolean;
  login: (email: string, pass: string) => Promise<void>;
  logout: () => void;
  openLoginModal: () => void;
  closeLoginModal: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('eduattack_token'));
  const [isChecking, setIsChecking] = useState<boolean>(true);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);

  useEffect(() => {
    if (!token) {
      setUser(null);
      setIsChecking(false);
      return;
    }

    apiClient
      .getMe()
      .then((userData) => {
        setUser(userData);
      })
      .catch(() => {
        localStorage.removeItem('eduattack_token');
        setToken(null);
        setUser(null);
      })
      .finally(() => {
        setIsChecking(false);
      });
  }, [token]);

  const login = async (email: string, pass: string) => {
    const res = await apiClient.login({ email, password: pass });
    localStorage.setItem('eduattack_token', res.access_token);
    setToken(res.access_token);
    setUser(res.user);
  };

  const logout = () => {
    localStorage.removeItem('eduattack_token');
    setToken(null);
    setUser(null);
  };

  const openLoginModal = () => setIsModalOpen(true);
  const closeLoginModal = () => setIsModalOpen(false);

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAdmin: user?.role === 'admin',
        isChecking,
        login,
        logout,
        openLoginModal,
        closeLoginModal,
      }}
    >
      {children}
      <LoginModal isOpen={isModalOpen} onClose={closeLoginModal} />
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

