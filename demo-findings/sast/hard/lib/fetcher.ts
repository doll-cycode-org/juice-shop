import axios from 'axios'

export async function fetchRemote (target: string, headers: Record<string, string>) {
  const response = await axios.get(target, { headers, responseType: 'arraybuffer', maxRedirects: 5 })
  return response.data
}
