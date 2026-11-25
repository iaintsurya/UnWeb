export const API_BASE_URL = (() => {
  let value = import.meta.env.VITE_API_BASE_URL ?? "";
  while (value.endsWith("/")) value = value.slice(0, -1);
  return value;
})();

type ApiErrorPayload = {
  detail?: string | { message?: string };
};

export function resolveApiUrl(path: string, baseUrl = API_BASE_URL): string {
  if (/^https?:\/\//i.test(path)) return path;
  return `${baseUrl}${path}`;
}

export async function apiRequest<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(resolveApiUrl(path), init);
  const payload: unknown = await response.json().catch(() => null);

  if (!response.ok) {
    const detail = (payload as ApiErrorPayload | null)?.detail;
    const message =
      typeof detail === "string"
        ? detail
        : detail?.message ?? `Request failed (${response.status}).`;
    throw new Error(message);
  }

  if (payload === null) {
    throw new Error("The API returned an empty or invalid JSON response.");
  }
  return payload as T;
}
