import { useEffect, useRef, useState } from "react";
import { ChatItem } from "./chat-item";
import { CtaCard } from "./cta-button";
import { BiSolidLeftArrow } from "react-icons/bi";
import { RiSendPlane2Line } from "react-icons/ri";
import { v4 as uuidv4 } from "uuid";

// Header Component
const Header = ({ title, onBack }: { title: string; onBack?: () => void }) => (
  <div className="bg-[#0057FF] text-white text-center p-4 py-8 rounded-t-[16px] flex items-center justify-between">
    {onBack && (
      <button
        onClick={onBack}
        className="text-white ml-2 flex gap-2 items-center absolute z-10 py-4"
      >
        <BiSolidLeftArrow />
        Voltar
      </button>
    )}
    <span className="absolute left-0 right-0">{title}</span>
  </div>
);

interface ChatMessage {
  conversation_id: string;
  last_message: {
    message: {
      message: string;
    };
    timestamp: string;
  };
  participants: string[];
}

const ChatList = ({ onSelectChat }: { onSelectChat: (id: string) => void }) => {
  const [chats, setChats] = useState<ChatMessage[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchChats = async () => {
      try {
        const response = await fetch(
          `${process.env.NEXT_PUBLIC_HOST}/conversations`,
          {
            headers: {
              "ngrok-skip-browser-warning": "true",
            },
          }
        );
        const data = await response.json();

        // Check if the data is an array
        if (Array.isArray(data)) {
          setChats(data);
        } else {
          // If it's not an array, handle it as an error
          setError("Invalid data format from backend");
        }
      } catch (err) {
        setError("Failed to fetch conversations");
      } finally {
        setLoading(false);
      }
    };

    fetchChats();
  }, []);

  if (loading) {
    return <div className="text-center p-6">Loading...</div>;
  }

  if (error) {
    return <div className="text-center p-6 text-red-500">Error: {error}</div>;
  }

  if (chats.length === 0) {
    return <div className="text-center p-6">Nenhuma conversa encontrada</div>;
  }

  return (
    <div className="p-6 overflow-auto h-[calc(100%-72px)]">
      {chats.map((chat) => (
        <div
          key={chat.conversation_id}
          onClick={() => onSelectChat(chat.conversation_id)}
        >
          <ChatItem
            message={
              chat.last_message?.message.message.substring(0, 25) +
                (chat.last_message?.message.message.length >= 24
                  ? "..."
                  : "") || "No messages yet"
            }
            timestamp={new Date(chat.last_message?.timestamp).toLocaleString(
              "pt-BR",
              {
                timeZone: "America/Sao_Paulo",
              }
            )}
            isUnread={false} // You can add logic to check if the message is unread
          />
        </div>
      ))}
    </div>
  );
};

// Footer Component
const Footer = ({ onNewChat }: { onNewChat: () => void }) => (
  <div className="absolute bottom-0 left-0 w-full p-4 bg-white">
    <CtaCard
      title="Iniciar nova conversa"
      description="Clique aqui para começar uma nova conversa"
      onClick={onNewChat}
    />
  </div>
);

// MessageBubble Component
const MessageBubble = ({
  message,
  type,
}: {
  message: string;
  type: "user" | "operator";
}) => {
  const bubbleStyles = {
    user: "bg-[#3047EC] text-white",
    operator: "bg-[#F2F2F2] text-black",
  };

  return (
    <div
      className={`inline-block px-4 py-2 rounded-2xl max-w-xs text-left ${bubbleStyles[type]}`}
    >
      {message}
    </div>
  );
};

// Função para obter ou gerar UUID
const getOrCreateUUID = () => {
  let uuid = localStorage.getItem("chat_uuid");
  if (!uuid) {
    uuid = uuidv4();
    localStorage.setItem("chat_uuid", uuid);
  }
  return uuid;
};

// ActiveChat Component (Chat ativo)
const ActiveChat = ({
  conversationId,
  onBack,
}: {
  conversationId: string;
  onBack: () => void;
}) => {
  const [messages, setMessages] = useState<
    {
      message: { message: string; type: "user" | "operator" };
    }[]
  >([]);
  const [inputMessage, setInputMessage] = useState("");
  const [ws, setWs] = useState<WebSocket | null>(null);
  const [isTyping, setIsTyping] = useState(false);

  // Create a ref for the chat container
  const chatContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Conectar ao WebSocket usando o conversationId
    const socket = new WebSocket(
      `${process.env.NEXT_PUBLIC_WS_HOST}/chat/${conversationId}`
    );

    socket.onopen = () => {
      console.log("Conexão WebSocket estabelecida");
    };

    socket.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (Array.isArray(data)) {
        // Histórico de mensagens
        setMessages(data);
      } else {
        // Nova mensagem
        setMessages((prevMessages) => [...prevMessages, data]);
      }

      if (data?.sender == "faq_service") {
        setIsTyping(false);
      }
    };

    setWs(socket);

    return () => {
      socket.close();
    };
  }, [conversationId]);

  useEffect(() => {
    // Scroll to the bottom whenever messages change
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop =
        chatContainerRef.current.scrollHeight;
    }
  }, [messages]);

  const handleSendMessage = () => {
    if (inputMessage.trim() && ws) {
      const newMessage = {
        message: { message: inputMessage, type: "user" as "user" | "operator" },
      };
      ws.send(JSON.stringify(newMessage.message));
      setMessages([...messages, newMessage]);
      setInputMessage(""); // Limpa o campo de input após o envio
      setIsTyping(true);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      handleSendMessage();
    }
  };

  return (
    <div className="relative h-full">
      <Header title="Conversa" onBack={onBack} />

      {/* Chat messages container with ref */}
      <div
        className="p-6 overflow-auto h-[calc(100%-120px)]"
        ref={chatContainerRef}
      >
        {messages.map((msg, index) => (
          <div
            key={index}
            className={`flex ${
              msg.message.type === "user" ? "justify-end" : "justify-start"
            } mb-4`}
          >
            <MessageBubble
              message={msg.message.message}
              type={msg.message.type}
            />
          </div>
        ))}
        {isTyping && (
          <div className="flex justify-start mb-4">
            <div className="inline-block px-4 py-4 rounded-2xl max-w-xs text-left bg-[#F2F2F2] text-black">
              <div className="flex items-center space-x-1">
                <div className="dot bg-gray-400 w-2 h-2 rounded-full animate-bounce delay-100"></div>
                <div className="dot bg-gray-400 w-2 h-2 rounded-full animate-bounce delay-200"></div>
                <div className="dot bg-gray-400 w-2 h-2 rounded-full animate-bounce delay-300"></div>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="absolute bottom-0 left-0 w-full p-4 bg-white flex items-center gap-2">
        <input
          type="text"
          value={inputMessage}
          onChange={(e) => setInputMessage(e.target.value)}
          placeholder="Digite sua mensagem..."
          className="border border-gray-300 p-2 rounded w-full"
          onKeyDown={handleKeyPress}
        />
        <button onClick={handleSendMessage} className="text-white rounded">
          <RiSendPlane2Line className="text-[#0057FF] w-10" />
        </button>
      </div>
    </div>
  );
};

// Main ChatContent Component
const ChatContent = () => {
  const [activeChat, setActiveChat] = useState(false);
  const [conversationId, setConversationId] = useState<string | null>(null);

  const handleSelectChat = (id: string) => {
    setConversationId(id);
    setActiveChat(true);
  };

  const handleNewChat = async () => {
    // Call the backend to create a new conversation
    const response = await fetch(
      `${process.env.NEXT_PUBLIC_HOST}/conversations/create`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "ngrok-skip-browser-warning": "true",
        },
        body: JSON.stringify({
          participants: [getOrCreateUUID()], // Add the current user as a participant
        }),
      }
    );

    const data = await response.json();
    setConversationId(data.conversation_id);
    setActiveChat(true);
  };

  const handleBackToChatList = () => {
    setActiveChat(false);
  };

  return (
    <div className="relative h-[85%]">
      {activeChat && conversationId ? (
        <ActiveChat
          conversationId={conversationId}
          onBack={handleBackToChatList}
        />
      ) : (
        <>
          <Header title="Conversas" />
          <ChatList onSelectChat={handleSelectChat} />
          <Footer onNewChat={handleNewChat} />
        </>
      )}
    </div>
  );
};

export { ChatItem, ChatContent };
