
interface StreamInterface {
  buffer: Uint32Array;
  length: number;
  state: Uint32Array;
  update(chunk: string | Uint32Array): StreamInterface;
  digest(): Uint32Array;
  digest(format: 'hex' | 'binary'): string;
}
