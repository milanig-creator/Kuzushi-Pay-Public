export class ApiError extends Error {}

export async function api<T>(url: string, body?: object, method: "POST" | "PUT" = "POST"): Promise<T> {
  const response = await fetch(url, body ? {
    method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
  } : undefined);
  const data = await response.json();
  if (!response.ok) throw new ApiError(data.error ?? "SERVER_ERROR");
  return data as T;
}
