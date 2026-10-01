import React, { Component, ErrorInfo, ReactNode } from 'react'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  }

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('SPAIDER UI Error:', error, errorInfo)
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: '100vh',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: '#0a0a0f',
          color: '#f0f0ff',
          fontFamily: 'Inter, sans-serif',
          padding: '2rem',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '3.5rem', marginBottom: '1rem' }}>🕷️</div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 800, color: '#00ffff', marginBottom: '0.5rem' }}>
            SPAIDER Command Center
          </h1>
          <p style={{ color: '#8888aa', maxWidth: '500px', marginBottom: '1.5rem' }}>
            A client-side initialization issue occurred. Click reload to refresh the dashboard.
          </p>
          <pre style={{
            background: '#12121e',
            border: '1px solid rgba(255,255,255,0.1)',
            padding: '1rem',
            borderRadius: '8px',
            color: '#ff4d6d',
            fontSize: '0.85rem',
            maxWidth: '600px',
            overflowX: 'auto',
            marginBottom: '1.5rem'
          }}>
            {this.state.error?.message || 'Unknown runtime error'}
          </pre>
          <button
            onClick={() => window.location.reload()}
            style={{
              background: 'linear-gradient(135deg, #00ffff, #0088ff)',
              color: '#0a0a0f',
              border: 'none',
              padding: '0.75rem 1.5rem',
              fontWeight: 700,
              borderRadius: '6px',
              cursor: 'pointer'
            }}
          >
            ↻ Reload Command Center
          </button>
        </div>
      )
    }

    return this.props.children
  }
}
