import Image from "next/image";
import Home from "../icons/home.svg";
import Help from "../icons/help.svg";
import Chat2 from "../icons/chat-2.svg";
import HomeActive from "../icons/home-active.svg";
import HelpActive from "../icons/help-active.svg";
import Chat2Active from "../icons/chat-2-active.svg";

const Navbar = ({
  activeTab,
  setActiveTab,
}: {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}) => {
  const tabs = [
    { icon: Home, activeIcon: HomeActive, label: "Inicio", key: "home" },
    { icon: Chat2, activeIcon: Chat2Active, label: "Conversas", key: "chat" },
    { icon: Help, activeIcon: HelpActive, label: "Ajuda", key: "help" },
  ];

  const color = {
    active: "text-[#3047EC]",
    normal: "text-black",
  };

  return (
    <div className="bg-white absolute bottom-5 w-full flex justify-center items-center gap-10">
      {tabs.map((tab) => (
        <div
          key={tab.key}
          className="flex flex-col gap-1 justify-center items-center cursor-pointer"
          onClick={() => setActiveTab(tab.key)}
        >
          <Image
            src={activeTab === tab.key ? tab.activeIcon : tab.icon}
            alt={tab.label}
            width="24"
            height="24"
          />
          <p
            className={`text-sm font-${
              activeTab === tab.key ? "semibold" : "normal"
            } ${activeTab === tab.key ? color.active : color.normal}`}
          >
            {tab.label}
          </p>
        </div>
      ))}
    </div>
  );
};

export { Navbar };
