import { create } from 'zustand'

type Mode = 'RED' | 'BLUE' | 'PURPLE'

interface SPAIDERStore {
  mode: Mode
  setMode: (mode: Mode) => void
  sidebarOpen: boolean
  toggleSidebar: () => void
}

export const useStore = create<SPAIDERStore>((set) => ({
  mode: 'BLUE',
  setMode: (mode) => set({ mode }),
  sidebarOpen: true,
  toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),
}))
