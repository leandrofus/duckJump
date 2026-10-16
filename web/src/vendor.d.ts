// asciinema-player ships no type definitions.
declare module 'asciinema-player' {
  export interface Player {
    dispose(): void
    play(): Promise<void>
    pause(): void
    seek(where: number | string): Promise<void>
  }
  export function create(src: string | { url: string; fetchOpts?: RequestInit } | { data: string }, elem: HTMLElement, opts?: Record<string, unknown>): Player
}
