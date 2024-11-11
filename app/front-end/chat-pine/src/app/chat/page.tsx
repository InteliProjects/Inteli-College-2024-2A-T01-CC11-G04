import { CustomerChat } from "@/components/customer-chat";

export default function ChatPage() {
  return (
    <div className="w-full h-full relative">
      <iframe
        src="https://brastelremit.jp/por/home"
        className="w-full h-full"
      />
      {/* Ajuste o CustomerChat para ficar absoluto e com z-index maior */}
      <CustomerChat classes="absolute bottom-0 right-0 z-10" />
    </div>
  );
}
