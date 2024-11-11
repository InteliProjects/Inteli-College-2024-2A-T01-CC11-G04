"use client";
import Image from "next/image";
import { useState } from "react";
import { Navbar } from "./navbar";
import { Input } from "./ui/input";
import { CtaCard } from "./cta-button";
import Chat from "../icons/chat.svg";
import { AppLogo } from "./ui/app-logo";
import { SearchCard } from "./search-card";
import ChevronDown from "../icons/chevron-down.svg";
import ChevronRight from "../icons/chevron-right.svg";
import { ChatContent } from "./chat-content";

// Sample content components for each tab
const HomeContent = () => (
  <div>
    <div className="absolute bg-custom-gradient w-full h-[40%] z-1">
      <div className="absolute bg-merge-gradient bottom-0 w-full h-[50%]" />
    </div>
    <div className="absolute top-0 w-full flex flex-col z-10 py-8 px-6">
      <AppLogo variant="white" size="sm" />
      <div className="flex flex-col gap-4 mt-8">
        <div>
          <h1 className="font-bold text-xl text-white opacity-50">Olá</h1>
          <h1 className="font-bold text-xl text-white">Como podemos ajudar?</h1>
        </div>
        <CtaCard
          title="Envie-nos uma mensagem"
          description="Normalmente respondemos em minutos"
          onClick={() => {}}
        />
        <SearchCard />
      </div>
    </div>
  </div>
);

const HelpContent = () => (
  <div className="relative h-full">
    <div className="bg-[#0057FF] text-white text-center p-4 rounded-t-[16px]">
      Ajuda
    </div>
    <div className="p-6">
      <div className="mb-4">
        <Input type="text" placeholder="Busque por ajuda" className="w-full" />
      </div>
      <div className="mb-4">
        <div className="flex justify-between items-center">
          <div>
            <p className="text-sm font-bold">Como fazer uma remessa?</p>
            <p className="text-xs text-gray-500">Lorem ipsum dolor sit amet</p>
          </div>
          <div>
            <Image src={ChevronRight} alt="Arrow Right" />
          </div>
        </div>
        <hr className="bg-[#F2F2F2] mt-4 mb-4" />
      </div>
      <div className="mb-4">
        <div className="flex justify-between items-center">
          <div>
            <p className="text-sm font-bold">Como criar uma conta?</p>
            <p className="text-xs text-gray-500">Lorem ipsum dolor sit amet</p>
          </div>
          <div>
            <Image src={ChevronRight} alt="Arrow Right" />
          </div>
        </div>
        <hr className="bg-[#F2F2F2] mt-4 mb-4" />
      </div>
      <div className="mb-4">
        <div className="flex justify-between items-center">
          <div>
            <p className="text-sm font-bold">Como consultar câmbios e taxas?</p>
            <p className="text-xs text-gray-500">Lorem ipsum dolor sit amet</p>
          </div>
          <div>
            <Image src={ChevronRight} alt="Arrow Right" />
          </div>
        </div>
        <hr className="bg-[#F2F2F2] mt-4 mb-4" />
      </div>
      <div className="mb-4">
        <div className="flex justify-between items-center">
          <div>
            <p className="text-sm font-bold">Esqueci minha senha, e agora?</p>
            <p className="text-xs text-gray-500">Lorem ipsum dolor sit amet</p>
          </div>
          <div>
            <Image src={ChevronRight} alt="Arrow Right" />
          </div>
        </div>
      </div>
    </div>
  </div>
);

const CustomerChat = ({ classes }: { classes?: string }) => {
  const [open, setOpen] = useState(false);
  const [activeTab, setActiveTab] = useState("home");

  const handleOpen = () => {
    setOpen(!open);
  };

  const renderContent = () => {
    switch (activeTab) {
      case "home":
        return <HomeContent />;
      case "chat":
        return <ChatContent />;
      case "help":
        return <HelpContent />;
      default:
        return <HomeContent />;
    }
  };

  return (
    <div className={`relative select-none z-20 ${classes}`}>
      {open && (
        <div className="absolute z-0 bottom-28 right-9 w-[29vw] h-[80vh] rounded-[16px] shadow-custom-drop bg-white speech-bubble overflow-hidden">
          {renderContent()}
          <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />
        </div>
      )}
      <div
        className="absolute bottom-9 right-9 w-12 h-12 flex items-center justify-center cursor-pointer bg-[#0057FF] rounded-full select-none"
        onClick={handleOpen}
      >
        {open ? (
          <Image src={ChevronDown} alt="Chat" width="12" height="7" />
        ) : (
          <Image src={Chat} alt="Chat" width="16" height="16" />
        )}
      </div>
    </div>
  );
};

CustomerChat.displayName = "CustomerChat";

export { CustomerChat };
