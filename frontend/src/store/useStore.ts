import { create } from 'zustand'

export type Mode = 'RED' | 'BLUE' | 'PURPLE'
export type CyberTheme = 'cyberpunk' | 'matrix' | 'crimson' | 'void' | 'synthwave' | 'quantum'
export type AnimationDimension = '4d' | '3d' | 'quantum' | 'matrix' | 'off'

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
}

const getSavedTheme = (): CyberTheme => {
  const saved = localStorage.getItem('spaider_theme') as CyberTheme
  return ['cyberpunk', 'matrix', 'crimson', 'void', 'synthwave', 'quantum'].includes(saved) ? saved : 'cyberpunk'
}

const getSavedAnim = (): AnimationDimension => {
  const saved = localStorage.getItem('spaider_anim') as AnimationDimension
  return ['4d', '3d', 'quantum', 'matrix', 'off'].includes(saved) ? saved : '4d'
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
}))
