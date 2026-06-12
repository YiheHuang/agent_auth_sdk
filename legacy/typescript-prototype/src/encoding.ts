// 这里提供少量编码工具，避免在签名链路里散落 Buffer/TextEncoder 细节。
export function toUint8Array(input: string | Uint8Array | undefined): Uint8Array {
  if (input === undefined) {
    // 空 body 也需要一个稳定表示，否则摘要会不一致。
    return new Uint8Array();
  }

  if (input instanceof Uint8Array) {
    return input;
  }

  return new TextEncoder().encode(input);
}

export function toBase64Url(input: Uint8Array): string {
  // base64url 适合放在 JSON 和 HTTP header 中，不需要再处理 "+" 和 "/"。
  return Buffer.from(input).toString("base64url");
}

export function fromBase64Url(input: string): Uint8Array {
  return new Uint8Array(Buffer.from(input, "base64url"));
}
