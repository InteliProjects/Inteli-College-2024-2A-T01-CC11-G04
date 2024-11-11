import Image from "next/image";
import { Input } from "./ui/input";
import ChevronRight from "../icons/chevron-right.svg";

const SearchCard = () => {
  return (
    <div className="flex flex-col gap-4 justify-between bg-white rounded-[10px] p-2 shadow-custom-drop-2">
      <Input type="text" placeholder="Busque por ajuda" className="w-full" />
      <div className="flex justify-between mx-2">
        <p className="text-sm font-normal">Como crio uma conta?</p>
        <Image src={ChevronRight} alt="Next" />
      </div>
      <div className="flex justify-between mx-2">
        <p className="text-sm font-normal">
          O que preciso para fazer uma remessa?
        </p>
        <Image src={ChevronRight} alt="Next" />
      </div>
      <div className="flex justify-between mx-2">
        <p className="text-sm font-normal">Confirmação de câmbio e taxas</p>
        <Image src={ChevronRight} alt="Next" />
      </div>
    </div>
  );
};

SearchCard.displayName = "SearchCard";

export { SearchCard };
