import { create } from 'zustand'

export type Mode = 'RED' | 'BLUE' | 'PURPLE'
export type CyberTheme = 'cyberpunk' | 'matrix' | 'crimson' | 'void' | 'synthwave' | 'quantum'
export type AnimationDimension = '4d' | '3d' | 'quantum' | 'matrix' | 'off'

export interface UserProfile {
  id: string
  username: string
  email: string
  full_name?: string
  role: string
  is_active?: boolean
}

interface SPAIDERStore {
  mode: Mode
  setMode: (mode: Mode) => void
  sidebarOpen: boolean
  toggleSidebar: () => void
  theme: CyberTheme
  setTheme: (theme: CyberTheme) => void
  animDimension: AnimationDimension
  setAnimDimension: (dim: AnimationDimension) => void
  animSpeed: number
  setAnimSpeed: (speed: number) => void
  animGlow: boolean
  setAnimGlow: (glow: boolean) => void
  holoViewerOpen: boolean
  setHoloViewerOpen: (open: boolean) => void
  currentUser: UserProfile | null
  setCurrentUser: (user: UserProfile | null, token?: string) => void
  logout: () => void
}

const getSavedTheme = (): CyberTheme => {
  const saved = localStorage.getItem('spaider_theme') as CyberTheme
  return ['cyberpunk', 'matrix', 'crimson', 'void', 'synthwave', 'quantum'].includes(saved) ? saved : 'cyberpunk'
}

const getSavedAnim = (): AnimationDimension => {
  const saved = localStorage.getItem('spaider_anim') as AnimationDimension
  return ['4d', '3d', 'quantum', 'matrix', 'off'].includes(saved) ? saved : '4d'
}

const getSavedUser = (): UserProfile | null => {
  try {
    const raw = localStorage.getItem('spaider_user')
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

export const useStore = create<SPAIDERStore>((set) => ({
  mode: 'BLUE',
  setMode: (mode) => set({ mode }),
  sidebarOpen: true,
  toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),

  theme: getSavedTheme(),
  setTheme: (theme) => {
    localStorage.setItem('spaider_theme', theme)
    document.documentElement.setAttribute('data-theme', theme)
    set({ theme })
  },

  animDimension: getSavedAnim(),
  setAnimDimension: (animDimension) => {
    localStorage.setItem('spaider_anim', animDimension)
    set({ animDimension })
  },

  animSpeed: 1,
  setAnimSpeed: (animSpeed) => set({ animSpeed }),

  animGlow: true,
  setAnimGlow: (animGlow) => set({ animGlow }),

  holoViewerOpen: false,
  setHoloViewerOpen: (holoViewerOpen) => set({ holoViewerOpen }),

  currentUser: getSavedUser() || {
    id: 'usr-admin-001',
    username: 'admin',
    email: 'admin@spaider.internal',
    full_name: 'Chief Information Security Officer',
    role: 'admin',
    is_active: true,
  },

  setCurrentUser: (user, token) => {
    if (user) {
      localStorage.setItem('spaider_user', JSON.stringify(user))
    } else {
      localStorage.removeItem('spaider_user')
    }
    if (token) {
      localStorage.setItem('spaider_token', token)
    } else if (token === '') {
      localStorage.removeItem('spaider_token')
    }
    set({ currentUser: user })
  },

  logout: () => {
    localStorage.removeItem('spaider_token')
    localStorage.removeItem('spaider_user')
    set({ currentUser: null })
  },
}))
