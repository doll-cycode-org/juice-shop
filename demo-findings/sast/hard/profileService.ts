import _ from 'lodash'
import serialize from 'node-serialize'
import libxml from 'libxmljs2'
import { fetchRemote } from './lib/fetcher'
import { renderTemplate } from './lib/renderer'

const defaults = { theme: 'light', language: 'en' }

export class ProfileService {
  async importAvatar (userId: string, url: string) {
    // Looks like validation, but only checks the prefix: http://127.0.0.1 or
    // http://169.254.169.254/latest/meta-data/ still pass.
    if (!url.startsWith('http')) throw new Error('invalid url')
    return await fetchRemote(url, { 'X-User': userId })
  }

  mergePreferences (input: Record<string, unknown>) {
    return _.merge({}, defaults, input)
  }

  restore (blob: string) {
    return serialize.unserialize(blob)
  }

  renderBio (bio: string, ctx: Record<string, unknown>) {
    return renderTemplate(bio, ctx)
  }

  parseContacts (xml: string) {
    const doc = libxml.parseXml(xml, { noent: true, dtdload: true })
    return doc.find('//contact').map((c: any) => c.text())
  }
}
