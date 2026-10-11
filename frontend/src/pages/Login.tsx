import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { authApi } from '../api/client'
import { useStore, UserProfile } from '../store/useStore'
import { Lock, User, Eye, EyeOff, ShieldAlert, CheckCircle2, ArrowRight, KeyRound, Terminal } from 'lucide-react'

export default function Login() {
  const navigate = useNavigate()
  const { setCurrentUser, theme } = useStore()

  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('admin123')
  const [showPassword, setShowPassword] = useState(false)
  const [rememberMe, setRememberMe] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  const handleQuickFill = (user: string, pass: string) => {
    setUsername(user)
    setPassword(pass)
    setError(null)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!username.trim() || !password) {
      setError('Please provide both username and password.')
      return
    }

    setLoading(true)
    setError(null)
    setSuccess(null)

    try {
      const res = await authApi.login(username.trim(), password)
      if (res && res.access_token) {
        const userProfile: UserProfile = res.user || {
          id: username.toLowerCase() === 'admin' ? 'usr-admin-001' : 'usr-analyst-002',
          username: username.toLowerCase(),
          email: `${username.toLowerCase()}@spaider.internal`,
          full_name: username.toLowerCase() === 'admin' ? 'Chief Information Security Officer' : 'Lead Security Researcher',
          role: username.toLowerCase() === 'admin' ? 'admin' : 'analyst',
          is_active: true,
        }

        setCurrentUser(userProfile, res.access_token)
        setSuccess(`Access granted. Welcome, ${userProfile.full_name || userProfile.username}!`)
        
        setTimeout(() => {
          navigate('/dashboard')
        }, 600)
      } else {
        throw new Error('Unexpected response format from authentication server')
      }
    } catch (err: any) {
      console.warn('API login failed, checking fallback...', err)
      const errorMsg =
        err?.response?.data?.detail ||
        err?.message ||
        'Authentication failed. Please verify credentials.'

      // If backend is not reached or error returned, provide clear guidance
      // Also allow local fallback if credentials match default demo accounts
      const lowerUser = username.trim().toLowerCase()
      if (
        (lowerUser === 'admin' && password === 'admin123') ||
        (lowerUser === 'analyst' && password === 'analyst123')
      ) {
        // Fallback for offline frontend demo environment
        const fallbackUser: UserProfile = {
          id: lowerUser === 'admin' ? 'usr-admin-001' : 'usr-analyst-002',
          username: lowerUser,
          email: `${lowerUser}@spaider.internal`,
          full_name: lowerUser === 'admin' ? 'Chief Information Security Officer (Local)' : 'Lead Security Researcher (Local)',
          role: lowerUser === 'admin' ? 'admin' : 'analyst',
          is_active: true,
        }
        setCurrentUser(fallbackUser, 'demo-session-token-' + Date.now())
        setSuccess(`Authenticated via local security override. Redirecting...`)
        setTimeout(() => {
          navigate('/dashboard')
        }, 700)
        return
      }

      setError(errorMsg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      width: '100vw',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'radial-gradient(ellipse at 50% 20%, rgba(13, 20, 36, 0.95) 0%, rgba(5, 7, 15, 0.98) 100%), #05070f',
      position: 'relative',
      overflow: 'hidden',
      padding: '24px',
      fontFamily: 'Inter, system-ui, sans-serif',
      boxSizing: 'border-box'
    }}>
      {/* Background Cyber Grid */}
      <div style={{
        position: 'absolute',
        inset: 0,
        backgroundImage: `
          linear-gradient(rgba(0, 229, 255, 0.04) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0, 229, 255, 0.04) 1px, transparent 1px)
        `,
        backgroundSize: '40px 40px',
        pointerEvents: 'none',
      }} />

      {/* Cyber Glowing Circles in Background */}
      <div style={{
        position: 'absolute',
        width: 600,
        height: 600,
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(0, 229, 255, 0.08) 0%, transparent 70%)',
        top: '-150px',
        right: '-100px',
        pointerEvents: 'none',
        filter: 'blur(50px)',
      }} />
      <div style={{
        position: 'absolute',
        width: 500,
        height: 500,
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(168, 85, 247, 0.07) 0%, transparent 70%)',
        bottom: '-120px',
        left: '-100px',
        pointerEvents: 'none',
        filter: 'blur(60px)',
      }} />

      {/* Login Card */}
      <div style={{
        position: 'relative',
        zIndex: 10,
        width: '100%',
        maxWidth: 480,
        background: 'rgba(15, 23, 42, 0.75)',
        backdropFilter: 'blur(20px)',
        border: '1px solid rgba(0, 229, 255, 0.25)',
        boxShadow: '0 20px 60px rgba(0, 0, 0, 0.7), 0 0 40px rgba(0, 229, 255, 0.1)',
        borderRadius: '16px',
        padding: '36px',
        boxSizing: 'border-box',
      }}>
        {/* Top Header */}
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 64,
            height: 64,
            borderRadius: '16px',
            background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.15), rgba(168, 85, 247, 0.25))',
            border: '1px solid rgba(0, 229, 255, 0.4)',
            boxShadow: '0 0 24px rgba(0, 229, 255, 0.25)',
            fontSize: '32px',
            marginBottom: 16,
          }}>
            🕷️
          </div>

          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 8,
            marginBottom: 6,
          }}>
            <h1 style={{
              margin: 0,
              fontSize: '1.85rem',
              fontWeight: 900,
              letterSpacing: '0.08em',
              background: 'linear-gradient(135deg, #00e5ff 0%, #38bdf8 50%, #c084fc 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              textTransform: 'uppercase',
            }}>
              SPAiDER
            </h1>
          </div>

          <div style={{
            fontSize: '0.75rem',
            fontWeight: 700,
            color: '#94a3b8',
            letterSpacing: '0.14em',
            textTransform: 'uppercase',
            marginBottom: 10,
          }}>
            Cyber Intelligence & Offensive SecOps
          </div>

          <div style={{
            display: 'inline-block',
            padding: '3px 10px',
            borderRadius: '999px',
            fontSize: '0.7rem',
            fontWeight: 800,
            letterSpacing: '0.12em',
            background: 'rgba(0, 229, 255, 0.1)',
            color: '#00e5ff',
            border: '1px solid rgba(0, 229, 255, 0.3)',
          }}>
            SECURE CLEARANCE LEVEL 4
          </div>
        </div>

        {/* Error message */}
        {error && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '12px 14px',
            borderRadius: '8px',
            background: 'rgba(239, 68, 68, 0.12)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            color: '#fca5a5',
            fontSize: '0.82rem',
            marginBottom: 20,
            lineHeight: 1.4,
          }}>
            <ShieldAlert size={20} style={{ color: '#ef4444', flexShrink: 0 }} />
            <div style={{ flex: 1 }}>{error}</div>
          </div>
        )}

        {/* Success message */}
        {success && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '12px 14px',
            borderRadius: '8px',
            background: 'rgba(34, 197, 94, 0.12)',
            border: '1px solid rgba(34, 197, 94, 0.4)',
            color: '#86efac',
            fontSize: '0.82rem',
            marginBottom: 20,
          }}>
            <CheckCircle2 size={20} style={{ color: '#22c55e', flexShrink: 0 }} />
            <div>{success}</div>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          {/* Username */}
          <div>
            <label style={{
              display: 'block',
              fontSize: '0.78rem',
              fontWeight: 700,
              color: '#cbd5e1',
              marginBottom: 6,
              letterSpacing: '0.05em',
              textTransform: 'uppercase',
            }}>
              Operator Username
            </label>
            <div style={{
              position: 'relative',
              display: 'flex',
              alignItems: 'center',
            }}>
              <div style={{
                position: 'absolute',
                left: 14,
                color: '#64748b',
                display: 'flex',
                alignItems: 'center',
                pointerEvents: 'none',
              }}>
                <User size={18} />
              </div>
              <input
                id="username-input"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username (e.g. admin or analyst)"
                autoComplete="username"
                required
                style={{
                  width: '100%',
                  padding: '12px 14px 12px 42px',
                  borderRadius: '8px',
                  background: 'rgba(15, 23, 42, 0.8)',
                  border: '1px solid rgba(148, 163, 184, 0.25)',
                  color: '#ffffff',
                  fontSize: '0.92rem',
                  outline: 'none',
                  transition: 'all 0.2s ease',
                  boxSizing: 'border-box',
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = '#00e5ff'
                  e.target.style.boxShadow = '0 0 12px rgba(0, 229, 255, 0.3)'
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = 'rgba(148, 163, 184, 0.25)'
                  e.target.style.boxShadow = 'none'
                }}
              />
            </div>
          </div>

          {/* Password */}
          <div>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: 6,
            }}>
              <label style={{
                fontSize: '0.78rem',
                fontWeight: 700,
                color: '#cbd5e1',
                letterSpacing: '0.05em',
                textTransform: 'uppercase',
              }}>
                Security Password
              </label>
              <span style={{ fontSize: '0.72rem', color: '#64748b' }}>
                Default: admin123
              </span>
            </div>

            <div style={{
              position: 'relative',
              display: 'flex',
              alignItems: 'center',
            }}>
              <div style={{
                position: 'absolute',
                left: 14,
                color: '#64748b',
                display: 'flex',
                alignItems: 'center',
                pointerEvents: 'none',
              }}>
                <Lock size={18} />
              </div>
              <input
                id="password-input"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                autoComplete="current-password"
                required
                style={{
                  width: '100%',
                  padding: '12px 44px 12px 42px',
                  borderRadius: '8px',
                  background: 'rgba(15, 23, 42, 0.8)',
                  border: '1px solid rgba(148, 163, 184, 0.25)',
                  color: '#ffffff',
                  fontSize: '0.92rem',
                  outline: 'none',
                  transition: 'all 0.2s ease',
                  boxSizing: 'border-box',
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = '#00e5ff'
                  e.target.style.boxShadow = '0 0 12px rgba(0, 229, 255, 0.3)'
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = 'rgba(148, 163, 184, 0.25)'
                  e.target.style.boxShadow = 'none'
                }}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                title={showPassword ? 'Hide password' : 'Show password'}
                style={{
                  position: 'absolute',
                  right: 12,
                  background: 'none',
                  border: 'none',
                  color: '#64748b',
                  cursor: 'pointer',
                  padding: 4,
                  display: 'flex',
                  alignItems: 'center',
                }}
              >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </div>

          {/* Remember session */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '0.8rem',
            color: '#94a3b8',
          }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                style={{ accentColor: '#00e5ff', cursor: 'pointer' }}
              />
              Remember session token
            </label>
            <span style={{ color: '#00e5ff', cursor: 'pointer', fontSize: '0.78rem' }} onClick={() => handleQuickFill('admin', 'admin123')}>
              Reset to Admin
            </span>
          </div>

          {/* Submit Button */}
          <button
            id="login-submit-btn"
            type="submit"
            disabled={loading}
            style={{
              marginTop: 6,
              width: '100%',
              padding: '13px 20px',
              borderRadius: '8px',
              border: '1px solid #00e5ff',
              background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.9) 0%, rgba(14, 165, 233, 0.9) 100%)',
              color: '#05070f',
              fontSize: '0.95rem',
              fontWeight: 800,
              letterSpacing: '0.06em',
              textTransform: 'uppercase',
              cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 10,
              boxShadow: '0 0 20px rgba(0, 229, 255, 0.4)',
              transition: 'all 0.2s ease',
              opacity: loading ? 0.7 : 1,
            }}
          >
            {loading ? (
              <>
                <div style={{
                  width: 16,
                  height: 16,
                  border: '2px solid #05070f',
                  borderTopColor: 'transparent',
                  borderRadius: '50%',
                  animation: 'spin 0.8s linear infinite',
                }} />
                Authenticating...
              </>
            ) : (
              <>
                Authorize & Launch <ArrowRight size={18} />
              </>
            )}
          </button>
        </form>

        {/* Quick Demo Credentials Panel */}
        <div style={{
          marginTop: 26,
          padding: '14px 16px',
          borderRadius: '10px',
          background: 'rgba(2, 6, 23, 0.65)',
          border: '1px solid rgba(148, 163, 184, 0.15)',
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            fontSize: '0.72rem',
            fontWeight: 800,
            color: '#94a3b8',
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            marginBottom: 10,
          }}>
            <KeyRound size={13} style={{ color: '#00e5ff' }} />
            One-Click Demo Credentials:
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            {/* Admin Preset */}
            <button
              type="button"
              onClick={() => handleQuickFill('admin', 'admin123')}
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'flex-start',
                padding: '9px 12px',
                borderRadius: '6px',
                background: username === 'admin' ? 'rgba(0, 229, 255, 0.12)' : 'rgba(15, 23, 42, 0.6)',
                border: username === 'admin' ? '1px solid #00e5ff' : '1px solid rgba(148, 163, 184, 0.18)',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'all 0.15s ease',
              }}
            >
              <div style={{ fontSize: '0.78rem', fontWeight: 800, color: '#00e5ff' }}>
                ⚡ Administrator
              </div>
              <div style={{ fontSize: '0.72rem', color: '#cbd5e1', marginTop: 2 }}>
                admin / admin123
              </div>
            </button>

            {/* Analyst Preset */}
            <button
              type="button"
              onClick={() => handleQuickFill('analyst', 'analyst123')}
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'flex-start',
                padding: '9px 12px',
                borderRadius: '6px',
                background: username === 'analyst' ? 'rgba(168, 85, 247, 0.12)' : 'rgba(15, 23, 42, 0.6)',
                border: username === 'analyst' ? '1px solid #a855f7' : '1px solid rgba(148, 163, 184, 0.18)',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'all 0.15s ease',
              }}
            >
              <div style={{ fontSize: '0.78rem', fontWeight: 800, color: '#c084fc' }}>
                🛡️ Security Analyst
              </div>
              <div style={{ fontSize: '0.72rem', color: '#cbd5e1', marginTop: 2 }}>
                analyst / analyst123
              </div>
            </button>
          </div>
        </div>

        {/* Direct bypass to dashboard */}
        <div style={{
          marginTop: 18,
          textAlign: 'center',
          fontSize: '0.76rem',
          color: '#64748b',
        }}>
          Skip to Command Center without logging in?{' '}
          <span
            onClick={() => navigate('/dashboard')}
            style={{
              color: '#38bdf8',
              cursor: 'pointer',
              fontWeight: 600,
              textDecoration: 'underline',
            }}
          >
            Enter as Guest Analyst
          </span>
        </div>
      </div>
    </div>
  )
}
