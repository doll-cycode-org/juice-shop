import _ from 'lodash'

export function renderTemplate (source: string, ctx: Record<string, unknown>) {
  return _.template(source)(ctx)
}
