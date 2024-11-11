import { CustomerChat } from "@/components/customer-chat";
import { LoginPage } from "@/components/login-page";

export default function Home() {
  return (
    <div className="flex h-full">
      <LoginPage />
      <CustomerChat />
    </div>
  );
}
