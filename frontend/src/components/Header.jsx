import React, { useContext } from "react";
import { AppContext } from "../context/AppContext.jsx";

const Header = () => {
  const { userData } = useContext(AppContext);
  return (
    <header>
      <h1>Welcome to MyApp</h1>
      {/* <h2>Hello {userData.name}</h2> */}
    </header>
  );
};

export default Header;
