"use client";
import Image from "next/image";
import { ChatItem } from "@/components/chat-item";
import { SectionTitle } from "@/components/section-title";
import LightningIcon from "../../../../icons/lightning.svg";

// ChatList Component
const ChatList = () => {
  const chats = [
    {
      message: "Você precisa acessar o seu e-mail...",
      timestamp: "Atendimento ao cliente · 1d atrás",
      isUnread: false,
    },
    {
      message: "Em torno de R$403,24",
      timestamp: "Atendimento ao cliente · 2d atrás",
      isUnread: false,
    },
    {
      message: "Oi! 👋 Como eu posso te ajudar?",
      timestamp: "Atendimento ao cliente · 4d atrás",
      isUnread: true,
    },
  ];

  return (
    <div className="p-6 h-fit">
      {chats.map((chat, index) => (
        <ChatItem
          key={index}
          message={chat.message}
          timestamp={chat.timestamp}
          isUnread={chat.isUnread}
        />
      ))}
    </div>
  );
};

// MessageBubble Component
const MessageBubble = ({
  message,
  type,
}: {
  message: string;
  type: "user" | "robot" | "operator";
}) => {
  // Define styles based on message type
  const bubbleStyles = {
    user: "bg-[#3047EC] text-white",
    robot: "bg-[#F2F2F2] text-black",
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

// ChatMessage Component
const ChatMessage = ({
  message,
  type,
  timestamp,
  perspective,
}: {
  message: string;
  type: "user" | "robot" | "operator";
  timestamp: string;
  perspective: "user" | "operator";
}) => {
  // Determine alignment based on the current perspective
  let alignment;
  if (perspective === "user") {
    alignment = type === "user" ? "justify-end" : "justify-start";
  } else {
    alignment = type === "operator" ? "justify-end" : "justify-start";
  }

  const isUser = type === "user";

  return (
    <div className={`flex ${alignment} mb-4`}>
      {/* Avatar for robot and operator, no avatar for user */}
      {!isUser && (
        <div className="flex items-start mr-2">
          {type === "robot" ? (
            <div className="w-8 h-8 bg-[#FFF4D0] rounded-full flex items-center justify-center">
              <Image
                src={LightningIcon}
                alt="Robot Icon"
                width={16}
                height={16}
              />
            </div>
          ) : (
            <div className="w-8 h-8 bg-gray-200 rounded-full"></div> // Placeholder for operator avatar
          )}
        </div>
      )}

      {/* Message bubble */}
      <div>
        <MessageBubble message={message} type={type} />
        <p className="text-xs text-gray-500 mt-1 text-left">{timestamp}</p>
      </div>
    </div>
  );
};

// ChatWindow Component
const ChatWindow = ({ perspective }: { perspective: "user" | "operator" }) => {
  const messages = [
    {
      message: "👋 Olá! Como eu posso ajudar?",
      type: "robot",
      timestamp: "Agora",
    },
    {
      message: "Desculpa, mas você está errado",
      type: "user",
      timestamp: "2m atrás · Visto",
    },
    {
      message: "Eu posso falar com uma pessoa por favor?",
      type: "user",
      timestamp: "2m atrás · Visto",
    },
    {
      message:
        "Sem problemas! Deixe-me conectá-lo a um agente de suporte ao cliente.",
      type: "robot",
      timestamp: "Agora",
    },
    {
      message: "Olá, meu nome é Lucas! Como posso te ajudar?",
      type: "operator",
      timestamp: "Agora",
    },
    {
      message: "Ufa! Finalmente um humano.",
      type: "user",
      timestamp: "Agora · Não visto ainda",
    },
  ];

  return (
    <div className="p-6 overflow-auto h-full">
      {messages.map((msg, index) => (
        <ChatMessage
          key={index}
          message={msg.message}
          type={msg.type as "user" | "robot" | "operator"}
          timestamp={msg.timestamp}
          perspective={perspective}
        />
      ))}
    </div>
  );
};

// Main Page Component
export default function Page() {
  return (
    <div className="flex flex-col gap-2 w-full">
      <SectionTitle title="Chats" />
      <div className="flex gap-2">
        <div className="border border-[#F5F5F5] rounded-xl p-4 h-[85vh] w-[30%]">
          <ChatList />
        </div>
        <div className="border border-[#F5F5F5] rounded-xl p-4 h-[85vh] overflow-hidden w-[70%]">
          <ChatWindow perspective={"operator"} />
        </div>
      </div>
    </div>
  );
}
