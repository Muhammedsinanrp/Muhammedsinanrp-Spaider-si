import { useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import { authApi } from '../api/client'

export default function Login() {
  const navigate = useNavigate()
  const location = useLocation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const response = await authApi.login(username.trim(), password)
      if (!response?.access_token) throw new Error('The server did not return an access token.')
      localStorage.setItem('spaider_token', response.access_token)
      if (response.user) localStorage.setItem('spaider_user', JSON.stringify(response.user))
      toast.success(`Welcome, ${response.user?.username || username.trim()}`)
      const requested = (location.state as any)?.from
      navigate(typeof requested === 'string' && requested.startsWith('/')
        ? requested
        : '/dashboard', { replace: true })
    } catch (err: any) {
      const message = err?.response?.data?.detail || err?.message || 'Login failed. Check your credentials and backend status.'
      setError(String(message))
      toast.error('Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'grid',
      placeItems: 'center',
      padding: 24,
      background: 'radial-gradient(circle at 15% 20%, rgba(0,229,255,0.09), transparent 30%), radial-gradient(circle at 85% 75%, rgba(168,85,247,0.10), transparent 32%), #070812',
      color: '#f0f0ff',
      fontFamily: 'var(--font-sans, Inter, system-ui, sans-serif)',
    }}>
      <div style={{ width: '100%', maxWidth: 440 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12, marginBottom: 24 }}>
          <div style={{ fontSize: 42, filter: 'drop-shadow(0 0 12px rgba(0,229,255,0.4))' }}>🕷️</div>
          <div>
            <div style={{ fontSize: '1.8rem', fontWeight: 900, letterSpacing: '0.16em', color: '#00e5ff' }}>SPAiDER</div>
            <div style={{ fontSize: '0.66rem', letterSpacing: '0.18em', color: '#a5a6c4' }}>SECURITY COMMAND PLATFORM</div>
          </div>
        </div>

        <div style={{
          padding: 28,
          borderRadius: 16,
          background: 'rgba(14,16,32,0.94)',
          border: '1px solid rgba(0,229,255,0.22)',
          boxShadow: '0 20px 70px rgba(0,0,0,0.36)',
        }}>
          <div style={{ marginBottom: 22 }}>
            <h1 style={{ fontSize: '1.35rem', margin: 0, letterSpacing: '0.04em' }}>Sign in</h1>
            <p style={{ color: '#9c9fbd', fontSize: '0.84rem', lineHeight: 1.55, margin: '8px 0 0' }}>
              Sign in to view saved scan jobs, evidence and findings. All API operations require an authenticated session.
            </p>
          </div>

          <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <label htmlFor="spaider-username" style={{ display: 'block', fontSize: '0.77rem', fontWeight: 700, marginBottom: 6, color: '#c8c9df' }}>
                Username
              </label>
              <input
                id="spaider-username"
                name="username"
                autoComplete="username"
                required
                minLength={3}
                maxLength={64}
                value={username}
                onChange={e => setUsername(e.target.value)}
                className="input"
                placeholder="Your SPAiDER username"
                style={{ width: '100%' }}
              />
            </div>

            <div>
              <label htmlFor="spaider-password" style={{ display: 'block', fontSize: '0.77rem', fontWeight: 700, marginBottom: 6, color: '#c8c9df' }}>
                Password
              </label>
              <input
                id="spaider-password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="input"
                placeholder="Enter your password"
                style={{ width: '100%' }}
              />
            </div>

            {error && (
              <div role="alert" style={{
                padding: 11,
                borderRadius: 8,
                border: '1px solid rgba(255,59,92,0.35)',
                background: 'rgba(255,59,92,0.08)',
                color: '#ff8b9e',
                fontSize: '0.78rem',
                lineHeight: 1.45,
              }}>{error}</div>
            )}

            <button type="submit" className="btn btn-primary" disabled={loading} style={{
              width: '100%',
              justifyContent: 'center',
              marginTop: 4,
              padding: '12px 16px',
              background: 'linear-gradient(135deg, #00e5ff, #a855f7)',
              color: '#070812',
              border: 0,
              fontWeight: 900,
              opacity: loading ? 0.7 : 1,
            }}>
              {loading ? 'Authenticating…' : 'Sign in securely →'}
            </button>
          </form>

          <div style={{ marginTop: 18, paddingTop: 14, borderTop: '1px solid rgba(255,255,255,0.07)', color: '#8588a8', fontSize: '0.7rem', lineHeight: 1.6 }}>
            Registration is disabled by default. For a fresh local development database, the seeded administrator may use the development default only; configure <code>SPAIDER_ADMIN_PASSWORD</code> before exposing the service or deploying it outside your lab.
          </div>
        </div>

        <div style={{ textAlign: 'center', marginTop: 15, color: '#656885', fontSize: '0.67rem' }}>
          SPAiDER · Authenticated access · Authorized lab testing only
        </div>
      </div>
    </div>
  )
}
