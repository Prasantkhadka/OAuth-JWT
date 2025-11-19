import React, { useContext } from "react";
import { AppContext } from "../context/AppContext.jsx";

const Header = () => {
  const { userData } = useContext(AppContext);
  return (
    <header className="flex flex-col items-center p-4">
      <h1>Welcome to MyApp</h1>
      <h2>Hello {userData?.name || "Guest"}</h2>
    </header>
  );
};

export default Header;
