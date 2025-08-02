using Emocare.Domain.Entities.Chat;
using Emocare.Domain.Enums.AiChat;
using Emocare.Domain.Enums.Auth;
using Emocare.Domain.Interfaces.Helper.AiChat;
using Emocare.Domain.Interfaces.Repositories.Chat;
using Emocare.Shared.Helpers.Api;
using Microsoft.Extensions.Configuration;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Emocare.Shared.Helpers.Chat
{
    public class OpenRouterStreamService:IOpenRouterStreamService
    {
            private readonly HttpClient _httpClient;
            private readonly IConfiguration _configuration;
            private readonly IChatSessionRepository _chatSessionRepository;
            private readonly IChatMessageRepository _chatMessageRepository;

            public OpenRouterStreamService(IConfiguration configuration, HttpClient httpClient,
                IChatMessageRepository chatMessageRepository, IChatSessionRepository sessionRepository)
            {
                _configuration = configuration;
                _httpClient = httpClient;
                _chatMessageRepository = chatMessageRepository;
                _chatSessionRepository = sessionRepository;
            }
            public async Task<ChatSession> StartNewSession(Guid userId)
            {
                var data = await _chatSessionRepository.SessionExist(userId);
                if (data == null)
                {
                    var session = new ChatSession
                    {
                        Id = Guid.NewGuid(),
                        UserId = userId,
                        StartedAt = DateTime.UtcNow,
                        Messages = new List<ChatMessage>()
                    };
                    await _chatSessionRepository.Add(session);
                    return session;
                }
                return data;

            }
            public async Task SaveMessageAsync(Guid userId, UserRoles sender, string message, Guid sessionId)
            {
                var Message = new ChatMessage
                {
                    ChatSessionId = sessionId,
                    UserId = userId,
                    Role = sender,
                    SentAt = DateTime.UtcNow,
                    Message = message
                };

                await _chatMessageRepository.Add(Message);
            }
            public async IAsyncEnumerable<string> StreamChatAsync(string prompt, JournalMode mode, string mood)
            {
                var systemPrompt = mode switch
                {
                    JournalMode.Emotional => "You are a compassionate and empathetic listener. Provide emotional support in a warm and understanding tone. Reflect on the user's feelings and gently validate their emotions without judgment.",
                    JournalMode.CBT => "You are a Cognitive Behavioral Therapy (CBT) assistant. Help the user explore their thoughts and emotions by identifying cognitive distortions and gently guiding them to reframe negative thinking. Respond like a supportive therapist using CBT principles.",
                    JournalMode.Journal => $"You are a motivational coach. Respond with a reflective, uplifting message or inspirational quote tailored to the user's current mood: {mood}. Your goal is to help the user feel seen and gently uplift their emotional state.",
                    _ => "Respond concisely and with care. Keep the tone supportive and emotionally intelligent."
                };

                var payload =
                new
                {
                    model = "openrouter/horizon-alpha",

                    //"openrouter/horizon-alpha"
                    stream = true,
                    messages = new[]
                {
                new{role = "system",content=systemPrompt},
                new{role = "user",content=prompt}
                }

                };
                var req = new HttpRequestMessage(HttpMethod.Post, "https://openrouter.ai/api/v1/chat/completions")
                {
                    Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")

                };

                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _configuration["OpenRouter:ApiKey"]);

                using var response = await _httpClient.SendAsync(req, HttpCompletionOption.ResponseHeadersRead);

                if (!response.IsSuccessStatusCode)
                {
                    var error = await response.Content.ReadAsStringAsync();
                    throw new BadRequestException($"OpenRouter API error: {response.StatusCode} - {error}");
                }

                using var stream = await response.Content.ReadAsStreamAsync();
                using var reader = new StreamReader(stream);

                while (!reader.EndOfStream)
                {
                    var line = await reader.ReadLineAsync();

                    if (string.IsNullOrWhiteSpace(line))
                        continue;

                    if (line.Trim() == "data: [DONE]")
                        yield break;

                    if (line.StartsWith("data: "))
                    {
                        var json = line.Substring(6);
                        string? content = null;

                        try
                        {
                            var doc = JsonDocument.Parse(json);
                            content = doc.RootElement
                                .GetProperty("choices")[0]
                                .GetProperty("delta")
                                .GetProperty("content")
                                .GetString();
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Stream parse error: {ex.Message}");
                        }

                        if (!string.IsNullOrEmpty(content))
                            yield return content;
                    }

                }

            }
        }
    }

