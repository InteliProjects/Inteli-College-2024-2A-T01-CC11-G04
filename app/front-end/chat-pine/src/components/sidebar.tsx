"use client";
import { useState } from "react";
import Link from "next/link";
import { AppLogo } from "./ui/app-logo";
import { ChevronDown, ChevronUp } from "lucide-react";
import { usePathname } from "next/navigation";
import {
  AiOutlineHome,
  AiFillHome,
  AiOutlineAppstore,
  AiFillAppstore,
  AiOutlineBulb,
  AiFillBulb,
  AiOutlineCustomerService,
  AiFillCustomerService,
  AiOutlineMessage,
  AiFillMessage,
} from "react-icons/ai";

// Reusable NavItem component
function NavItem({
  label,
  href,
  shortcut,
  isActive,
  iconOutline,
  iconFilled,
}: {
  label: string;
  href: string;
  shortcut?: string;
  isActive: boolean;
  iconOutline: React.ReactNode;
  iconFilled: React.ReactNode;
}) {
  return (
    <li>
      <Link href={href} legacyBehavior>
        <a
          className={`flex justify-between items-center p-2 rounded-xl ${
            isActive ? "bg-[#FCFCFC] font-medium" : "text-gray-700"
          }`}
        >
          <span className="flex items-center space-x-2">
            <span>{isActive ? iconFilled : iconOutline}</span>
            <span className="text-xs">{label}</span>
          </span>
          {shortcut && (
            <span className="flex justify-center items-center w-11 bg-[#F0F0F0] text-[#8C8C8C] px-2 py-1 rounded-[6px] text-xs">
              {shortcut}
            </span>
          )}
        </a>
      </Link>
    </li>
  );
}

// Collapsible Section component
function CollapsibleSection({
  title,
  children,
  isOpen,
  toggleOpen,
}: {
  title: string;
  children: React.ReactNode;
  isOpen: boolean;
  toggleOpen: () => void;
}) {
  return (
    <div>
      <div
        className="flex justify-between items-center cursor-pointer text-[#8C8C8C] mt-4"
        onClick={toggleOpen}
      >
        <span className="text-xs">{title}</span>
        {isOpen ? (
          <ChevronUp size={16} color="#8C8C8C" />
        ) : (
          <ChevronDown size={16} color="#8C8C8C" />
        )}
      </div>
      {isOpen && <ul className="space-y-2 mt-4">{children}</ul>}
    </div>
  );
}

export default function Sidebar() {
  const pathname = usePathname();
  const [isSuporteOpen, setIsSuporteOpen] = useState(true);

  // Function to check if the current route matches the href
  const isActive = (href: string) => pathname === href;

  return (
    <div className="border border-[#F5F5F5] rounded-xl w-[20vw]">
      <div className="p-6">
        <AppLogo size="sm" variant="black" />
      </div>

      <nav className="p-4">
        <ul className="space-y-1">
          {/* Main navigation items */}
          <NavItem
            label="Início"
            href="/dashboard"
            shortcut="⌘ H"
            isActive={isActive("/dashboard")}
            iconOutline={<AiOutlineHome />}
            iconFilled={<AiFillHome />}
          />
          <NavItem
            label="Modelos"
            href="/dashboard/modelos"
            shortcut="⌘ M"
            isActive={isActive("/dashboard/modelos")}
            iconOutline={<AiOutlineAppstore />}
            iconFilled={<AiFillAppstore />}
          />
          <NavItem
            label="Intenções"
            href="/dashboard/intencoes"
            shortcut="⌘ I"
            isActive={isActive("/dashboard/intencoes")}
            iconOutline={<AiOutlineBulb />}
            iconFilled={<AiFillBulb />}
          />
          <NavItem
            label="Atendentes"
            href="/dashboard/atendentes"
            shortcut="⌘ A"
            isActive={isActive("/dashboard/atendentes")}
            iconOutline={<AiOutlineCustomerService />}
            iconFilled={<AiFillCustomerService />}
          />

          {/* Collapsible Suporte section */}
          <CollapsibleSection
            title="Suporte"
            isOpen={isSuporteOpen}
            toggleOpen={() => setIsSuporteOpen(!isSuporteOpen)}
          >
            <NavItem
              label="Chats"
              href="/dashboard/suporte/chats"
              isActive={isActive("/dashboard/suporte/chats")}
              iconOutline={<AiOutlineMessage />}
              iconFilled={<AiFillMessage />}
            />
          </CollapsibleSection>
        </ul>
      </nav>
    </div>
  );
}
