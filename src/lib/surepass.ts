// Surepass HTTP client wrapper — centralises auth headers, base URL, and error normalisation for all Surepass API calls

const SUREPASS_BASE_URL = 'https://kyc-api.surepass.io/api/v1'

export interface SurepassResponse<T = unknown> {
  success:    boolean
  message:    string
  status_code: number
  data:       T
}

export class SurepassError extends Error {
  constructor(
    public readonly endpoint: string,
    public readonly statusCode: number,
    message: string,
  ) {
    super(`Surepass [${statusCode}] ${endpoint}: ${message}`)
    this.name = 'SurepassError'
  }
}

export class SurepassClient {
  private readonly apiKey: string

  constructor() {
    const key = process.env.SUREPASS_API_KEY
    if (!key) console.warn('[surepass] SUREPASS_API_KEY not set — KYC verification calls will fail at runtime')
    this.apiKey = key ?? ''
  }

  /**
   * Makes an authenticated POST request to a Surepass endpoint.
   *
   * TODO: add retry logic (3 attempts, exponential back-off) for 5xx errors
   * TODO: add a configurable request timeout (default 10 s) via AbortController
   * TODO: normalise Surepass error shapes into SurepassError before re-throwing
   */
  async post<T = unknown>(endpoint: string, payload: unknown): Promise<SurepassResponse<T>> {
    // TODO: construct full URL from SUREPASS_BASE_URL + endpoint
    // TODO: set Authorization: Bearer <apiKey>, Content-Type: application/json headers
    // TODO: call fetch(), check res.ok, parse JSON, return typed SurepassResponse<T>
    void endpoint
    void payload
    throw new Error(`SurepassClient.post(${endpoint}): not implemented`)
  }
}

// Singleton — import and use this everywhere instead of constructing a new client per request
export const surepass = new SurepassClient()
