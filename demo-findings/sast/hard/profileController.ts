// DEMO FINDING (SAST / hard): inter-procedural, cross-file taint.
// Sources live here; sinks live in profileService.ts and lib/fetcher.ts / lib/renderer.ts.
// The scanner has to follow the data through 2-3 function calls across files.
import { type Request, type Response } from 'express'
import { ProfileService } from './profileService'

const service = new ProfileService()

function normalize (input: unknown): string {
  return String(input).trim()
}

export async function importAvatar (req: Request, res: Response) {
  // Source -> normalize() -> ProfileService.importAvatar() -> fetchRemote() (SSRF, CWE-918)
  const avatarUrl = normalize(req.body.avatarUrl)
  const image = await service.importAvatar(req.params.userId, avatarUrl)
  res.type('png').send(image)
}

export function updatePreferences (req: Request, res: Response) {
  // Source -> ProfileService.mergePreferences() -> lodash.merge (prototype pollution, CWE-1321)
  const prefs = service.mergePreferences(req.body)
  res.json(prefs)
}

export function restoreSession (req: Request, res: Response) {
  // Source (cookie) -> base64 decode -> ProfileService.restore() -> node-serialize.unserialize (RCE, CWE-502)
  const blob = Buffer.from(req.cookies.profile ?? '', 'base64').toString()
  res.json(service.restore(blob))
}

export function renderBio (req: Request, res: Response) {
  // Source -> ProfileService.renderBio() -> renderTemplate() -> _.template (SSTI / code injection, CWE-94)
  res.send(service.renderBio(req.query.bio as string, { name: req.query.name }))
}

export function importContacts (req: Request, res: Response) {
  // Source (raw XML body) -> ProfileService.parseContacts() -> libxmljs with noent (XXE, CWE-611)
  res.json(service.parseContacts(req.body.toString()))
}
