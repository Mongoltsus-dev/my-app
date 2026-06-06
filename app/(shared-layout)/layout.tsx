import Navbar from "@/components/web/Navbar";
import Sidebar from "@/components/web/Sidebar";
import { ReactNode } from "react";

export default function SharedLayout({ children }: { children: ReactNode }) {
  return (
    <>
      <Navbar />
      <div className="flex">
        <Sidebar />
        <main className="app-page flex-1 min-w-0 overflow-x-hidden pt-32 md:pt-24 pb-8 min-h-[calc(100vh-5rem)] transition-colors">
          <div className="w-full max-w-420 mx-auto px-4 md:px-6 lg:px-8">
            {children}
          </div>
        </main>
      </div>
    </>
  );
}
