"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Sidebar from "@/components/sidebar";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [loading, setLoading] = useState(true);
  const router = useRouter(); // Hook para navegação

  // Verifica se o token está presente no sessionStorage
  useEffect(() => {
    const token = sessionStorage.getItem("access_token");
    if (!token) {
      // Se não houver token, redireciona para a página de login
      router.push("/");
    } else {
      // Se o token estiver presente, para o loading
      setLoading(false);
    }
  }, [router]);

  // Spinner simples
  const Spinner = () => (
    <div className="flex justify-center items-center h-screen">
      <div className="w-16 h-16 border-4 border-blue-500 border-t-transparent border-solid rounded-full animate-spin"></div>
    </div>
  );

  return loading ? (
    <Spinner /> // Exibe o spinner enquanto está carregando
  ) : (
    <div className="bg-[#FCFCFC] p-3 flex gap-2 w-screen h-screen">
      <Sidebar />
      {children}
    </div>
  );
}
