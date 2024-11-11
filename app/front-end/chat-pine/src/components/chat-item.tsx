import Image from "next/image";
import ChevronRight from "../icons/chevron-right.svg";

// ChatItem Component
const ChatItem = ({
  message,
  timestamp,
  isUnread,
}: {
  message: string;
  timestamp: string;
  isUnread: boolean;
}) => (
  <div className="mb-4 cursor-pointer hover:bg-gray-100 p-2 rounded-[8px]">
    <div className="flex justify-between items-center">
      <div>
        <p className={`text-sm ${isUnread ? "font-bold" : ""}`}>{message}</p>
        <p className="text-xs text-gray-500">{timestamp}</p>
      </div>
      <div className="flex items-center">
        {isUnread ? (
          <span className="text-red-500 text-lg">•</span>
        ) : (
          <Image src={ChevronRight} alt="Arrow Right" />
        )}
      </div>
    </div>
  </div>
);

export { ChatItem };
