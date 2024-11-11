import Image from "next/image";
import SendIcon from "../icons/send-icon.svg";

interface CtaCardProps {
  title: string;
  description: string;
  onClick: () => void;
}

const CtaCard = ({ title, description, onClick }: CtaCardProps) => {
  return (
    <div
      className="flex justify-between bg-white rounded-[10px] p-5 shadow-custom-drop-2 cursor-pointer"
      onClick={onClick}
    >
      <div className="flex flex-col">
        <h1 className="font-semibold text-sm text-black">{title}</h1>
        <h1 className="font-normal text-sm text-black">{description}</h1>
      </div>
      <Image src={SendIcon} alt="Send" />
    </div>
  );
};

CtaCard.displayName = "CtaCard";

export { CtaCard };
