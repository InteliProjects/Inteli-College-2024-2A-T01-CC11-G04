import { cn } from "@/lib/utils";

const AppLogo = ({
  variant = "black",
  size = "lg",
}: {
  variant?: "black" | "white";
  size?: "sm" | "lg";
}) => {
  const textColor = variant === "white" ? "text-white" : "text-[#4A4543]";
  const bgColor = variant === "white" ? "bg-white" : "bg-[#4A4543]";
  const fontSize = size === "sm" ? "text-sm" : "text-xl";
  const circleSize = size === "sm" ? "w-2 h-2" : "w-3 h-3";

  return (
    <div className="flex items-center gap-2">
      <div className={cn(bgColor, circleSize, "rounded-full")}></div>
      <p className={cn(textColor, fontSize, "font-semibold")}>BrastelCom</p>
    </div>
  );
};

AppLogo.displayName = "AppLogo";

export { AppLogo };
