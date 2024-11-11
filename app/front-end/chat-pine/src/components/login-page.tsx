"use client";
import { useState } from "react";
import { useRouter } from "next/navigation"; // Importa o hook de navegação
import { AppLogo } from "./ui/app-logo";
import { Button } from "./ui/button";
import { Copyright } from "./ui/copyright";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { toast } from "react-hot-toast";
import axios from "axios";

export function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter(); // Hook para navegação

  const handleSubmit = async (e: React.MouseEvent<HTMLButtonElement>) => {
    e.preventDefault(); // Previne o comportamento padrão do botão
    setLoading(true);

    try {
      const response = await axios.post(
        `${process.env.NEXT_PUBLIC_HOST}/token`,
        {
          username: email,
          password: password,
        }
      );

      if (response.status === 200) {
        // Se a resposta for OK, salva o token no sessionStorage
        sessionStorage.setItem("access_token", response.data.access_token);
        toast.success("Login realizado com sucesso!");

        // Redireciona para o dashboard
        router.push("/dashboard");
      }
    } catch (error) {
      // Caso haja algum erro na requisição
      toast.error("Erro ao tentar fazer login. Verifique suas credenciais.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex h-full">
      {/* Left side */}
      <div className="w-[65vw] h-full flex flex-col justify-between p-9">
        <AppLogo />
        <div className="flex w-full justify-center">
          <div className="flex flex-col gap-8 w-[50%]">
            <div className="flex flex-col gap-4">
              <h1 className="text-5xl text-[#4A4543]">Bem-vindo(a)</h1>
              <h2 className="text-base text[#808080]">
                Por favor, insira suas credenciais de acesso.
              </h2>
            </div>
            {/* Removemos o form e substituímos por uma div */}
            <div className="flex flex-col gap-4">
              <div className="flex flex-col gap-2">
                <Label htmlFor="email">E-mail</Label>
                <Input
                  type="email"
                  placeholder="Digite seu e-mail"
                  id="email"
                  name="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
              <div className="flex flex-col gap-2">
                <Label htmlFor="password">Senha</Label>
                <Input
                  type="password"
                  placeholder="Digite sua senha"
                  id="password"
                  name="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
              <div className="flex justify-between w-full">
                <div className="flex gap-2 w-fit items-center">
                  <Input
                    type="checkbox"
                    id="remember-me"
                    name="remember-me"
                    className="!w-[16px] h-[16px]"
                  />
                  <Label htmlFor="remember-me">Lembrar por 30 dias</Label>
                </div>
                <a className="decoration-none text-[#4a4a4a] w-fit text-sm font-normal cursor-pointer">
                  Esqueci minha senha
                </a>
              </div>
              <Button
                type="button" // Mudamos o tipo do botão para "button" ao invés de "submit"
                className="w-full h-12 bg-[#0057FF] text-white font-base rounded-[8px]"
                disabled={loading}
                onClick={handleSubmit} // Usamos onClick para chamar handleSubmit
              >
                {loading ? "Entrando..." : "Entrar"}
              </Button>
            </div>
          </div>
        </div>
        <Copyright />
      </div>
      {/* Right side */}
      <div className="w-[35vw] h-full bg-[#FAFBFD] flex items-center">
        <div className="relative flex justify-center items-center w-[450px] h-[260px]">
          <div className="absolute w-[160px] h-[160px] bg-[#0057FF] rounded-full"></div>
          <div className="absolute w-full h-[150px] backdrop-blur-2xl bottom-[-100px] transform -translate-y-1/2 z-10"></div>
        </div>
      </div>
    </div>
  );
}
