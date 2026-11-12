// Usage: dotnet /app/probe/HealthProbe.dll [url]
// Exits 0 when the URL answers 2xx within 3 seconds, and 1 otherwise. It never prints the response.
using var http = new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) {
    Timeout = TimeSpan.FromSeconds(3),
};
var url = args.Length > 0 ? args[0] : "http://127.0.0.1:8080/readyz";
try {
    using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
    return response.IsSuccessStatusCode ? 0 : 1;
} catch (Exception) {
    return 1;
}
